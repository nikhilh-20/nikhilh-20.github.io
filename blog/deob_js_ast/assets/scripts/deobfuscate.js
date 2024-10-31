const esprima = require("esprima");
const estraverse = require("estraverse");
const escodegen = require("escodegen");
const fs = require("fs");

function find_declared_variables(ast) {
    const declared_vars = new Set();

    estraverse.traverse(ast, {
        enter(node)
        {
            // Find variable declarations and track their names
            if (node.type === "VariableDeclarator" && node.id.type === "Identifier")
                declared_vars.add(node.id.name);
        }
    });

    return declared_vars;
}

function find_used_variables(ast) {
    const used_vars = new Set();

    estraverse.traverse(ast, {
        enter(node, parent)
        {
            // Only add variables to used_vars if current node is not a declaration statement
            if (node.type === "Identifier" && !(parent && parent.type === "VariableDeclarator" && parent.id === node))
                used_vars.add(node.name);
        }
    });
    
    return used_vars;
}

function remove_unused_variables(ast, declared_vars, used_vars) {
    // unused_vars are those variables which were declared but not reused
    const unused_vars = new Set([...declared_vars].filter(var_name => !used_vars.has(var_name)));

    estraverse.replace(ast, {
        enter(node)
        {
            // Get the declaration statement
            if (node.type === "VariableDeclaration") {
                /* Remove declaration statements of unused variables and replace the current node's
                   declarations with the result */
                node.declarations = node.declarations.filter(decl => !unused_vars.has(decl.id.name));
                // If the unused variable was the only declaration, then remove the entire statement
                if (node.declarations.length === 0)
                    // Remove current node from parent array
                    return this.remove();
            }
        }
    });
}

function simplify_self_invoking_functions(ast) {
    estraverse.replace(ast, {
        enter(node)
        {
            // Check if a function has exactly three statements
            if (node.type === "FunctionDeclaration" && node.body.body.length === 3)
            {
                const [var_decl, self_assign, return_call] = node.body.body;

                // Check if the first statement is a variable declaration
                if (var_decl.type === "VariableDeclaration" && var_decl.declarations.length === 1)
                {
                    const var_declarator = var_decl.declarations[0];

                    /* Check if the second statement assigns the current function to a different function
                       that only returns the previously declared variable */
                    if (self_assign.type === "ExpressionStatement" &&
                        self_assign.expression.type === "AssignmentExpression" &&
                        self_assign.expression.operator === "=" &&
                        self_assign.expression.left.name === node.id.name &&
                        self_assign.expression.right.type === "FunctionExpression" &&
                        self_assign.expression.right.body.body.length === 1 &&
                        self_assign.expression.right.body.body[0].type === "ReturnStatement" &&
                        self_assign.expression.right.body.body[0].argument.name === var_declarator.id.name)
                    {
                        // Check if the third statement is a return statement that calls the modified function
                        if (return_call.type === "ReturnStatement" &&
                            return_call.argument.type === "CallExpression" &&
                            return_call.argument.callee.name === node.id.name)
                        {
                            /* All conditions have been satisfied. Simplify the current function to a
                               single return statement returning the variable's initialization value */
                            return {
                                type: "FunctionDeclaration",
                                id: node.id,
                                params: [],
                                body: {
                                    type: "BlockStatement",
                                    body: [
                                        {
                                            type: "ReturnStatement",
                                            argument: var_declarator.init,
                                        },
                                    ],
                                },
                                generator: false,
                                expression: false,
                                async: false,
                            };
                        }
                    }
                }
            }
        },
    });
}

function matches_hex_decode_signature(function_node) {
    let step = 0;
    let numeric = false, upper_alpha = false, lower_alpha = false

    estraverse.traverse(function_node.body, {
        enter(node)
        {
            switch (step)
            {
                case 0:
                    // The first pattern to match is the update expression in the for loop
                    if (node.type === "ForStatement" &&
                        node.update && node.update.type === "AssignmentExpression" &&
                        node.update.operator === "+=" &&
                        node.update.right.type === "Literal" && node.update.right.value === 2)
                        step++;
                    break;

                case 1:
                    // The second pattern to match is a substr() call
                    if (node.type === "CallExpression" &&
                        node.callee && node.callee.property && node.callee.property.name === "substr" &&
                        node.arguments.length === 2 && node.arguments[1].type === "Literal" &&
                        node.arguments[1].value === 2)
                        step++;
                    break;

                case 2:
                    // The third pattern to match is the update expression in another for loop
                    if (node.type === "ForStatement" &&
                        node.update && node.update.type === "UpdateExpression" &&
                        node.update.operator === "++")
                        step++;
                    break;

                case 3:
                    // The fourth pattern to match is a charAt() call
                    if (node.type === "CallExpression" &&
                        node.callee && node.callee.property && node.callee.property.name === "charAt" &&
                        node.arguments.length === 1 && node.arguments[0].type === "Identifier")
                        step++;
                    break;

                case 4:
                    /* The fifth, sixth and seventh patterns can occur in any order and involve comparison with
                       alphanumeric characters */
                    if (node.type === "BinaryExpression") {
                        if ((node.operator === ">=" && node.right.type === "Literal" && node.right.value === "0") ||
                            (node.operator === "<=" && node.right.type === "Literal" && node.right.value === "9"))
                            numeric = true;

                        if ((node.operator === ">=" && node.right.type === "Literal" && node.right.value === "A") ||
                            (node.operator === "<=" && node.right.type === "Literal" && node.right.value === "F"))
                            upper_alpha = true;

                        if ((node.operator === ">=" && node.right.type === "Literal" && node.right.value === "a") ||
                            (node.operator === "<=" && node.right.type === "Literal" && node.right.value === "f"))
                            lower_alpha = true;
                    }

                    if (numeric && upper_alpha && lower_alpha)
                        step++;

                    break;
            }
        }
    });

    // Only return True if all steps in the sequence matched
    return step === 5;
}

function rename_function(ast) {
    let original_function_name = null;

    // First pass: rename the function itself if it matches the signature
    estraverse.traverse(ast, {
        enter(node)
        {
            if (node.type === "FunctionDeclaration") {
                if (matches_hex_decode_signature(node)) {
                    original_function_name = node.id.name;
                    node.id.name = "hex_decode";
                }
            }
        },
    });

    // Second pass: rename any CallExpression references to the original function
    if (original_function_name) {
        estraverse.traverse(ast, {
            enter(node)
            {
                if (node.type === "CallExpression" &&
                    node.callee.type === "Identifier" &&
                    node.callee.name === original_function_name)
                    node.callee.name = "hex_decode";
            },
        });
    }
}

function process_JS_file(inputPath, outputPath) {
    const code = fs.readFileSync(inputPath, "utf-8");
    
    // Generate AST
    const ast = esprima.parseScript(code);

    // Find all declared and used variables
    // Then remove unused variables based on the difference
    const declared_vars = find_declared_variables(ast);
    const used_vars = find_used_variables(ast);
    remove_unused_variables(ast, declared_vars, used_vars);
    
    // Match signature and rename function
    rename_function(ast);
    
    // Simplify self-invoking functions
    simplify_self_invoking_functions(ast);

    // Generate cleaned JavaScript code
    const cleanedCode = escodegen.generate(ast);

    // Write the cleaned code to an output file
    fs.writeFileSync(outputPath, cleanedCode);
    console.log(`Cleaned JavaScript code has been written to ${outputPath}`);
}

const inputFilePath = "path\\to\\sample.js";
const outputFilePath = "path\\to\\cleaned_sample.js";

process_JS_file(inputFilePath, outputFilePath);
