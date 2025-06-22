#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <functional>
#include <sstream>
#include <cctype>
#include <stdexcept>

using namespace std;

/** Type definition for callable functions in expressions */
using Func = function<int(vector<int>)>;

/** Registered functions that can be invoked in expressions */
map<string, Func> functionRegistry =
{
    {
        "fn1", [](vector<int> args)
        {
            return args.empty() ? 0 : args[0];
        }
    },
    {
        "fn2", [](vector<int> args)
        {
            return args.empty() ? 0 : args[0];
        }
    },
    {
        "fn3", [](vector<int>)
        {
            return 9;
        }
    },
    {
        "isEven", [](vector<int> args)
        {
            return args[0] % 2 == 0;
        }
    },
    {
        "isPositive", [](vector<int> args)
        {
            return args[0] > 0;
        }
    },
    {
        "alwaysTrue", [](vector<int>)

        {
            return 1;
        }
    },
    {
        "alwaysFalse", [](vector<int>)
        {
            return 0;
        }
    }
};

/** Abstract base class for all AST nodes */
struct ASTNode
{
    /** Evaluate the node and return boolean result */
    virtual bool evaluate() = 0;
    virtual ~ASTNode() = default;
};

using AST = shared_ptr<ASTNode>;

/** Represents a numeric constant value */
struct ValueNode : ASTNode
{
    int value;
    explicit ValueNode(int v) : value(v) {}
    bool evaluate() override
    {
        return value != 0;
    }
    int getValue() const
    {
        return value;
    }
};

/** Represents a function call */
struct FuncNode : ASTNode
{
    string name;
    vector<int> args;
    FuncNode(string n, vector<int> a) : name(move(n)), args(move(a)) {}
    bool evaluate() override
    {
        return functionRegistry[name](args) != 0;
    }
    int getValue() const
    {
        return functionRegistry[name](args);
    }
};

/** Logical NOT */
struct NotNode : ASTNode
{
    AST child;
    explicit NotNode(AST c) : child(move(c)) {}
    bool evaluate() override
    {
        return !child->evaluate();
    }
};

/** Logical AND */
struct AndNode : ASTNode
{
    AST left, right;
    AndNode(AST l, AST r) : left(move(l)), right(move(r)) {}
    bool evaluate() override
    {
        return left->evaluate() && right->evaluate();
    }
};

/** Logical OR */
struct OrNode : ASTNode
{
    AST left, right;
    OrNode(AST l, AST r) : left(move(l)), right(move(r)) {}
    bool evaluate() override
    {
        return left->evaluate() || right->evaluate();
    }
};

/** Comparison operations */
struct ComparisonNode : ASTNode
{
    enum class Operator { EQ, NEQ, GT, LT, GTE, LTE };
    AST left;
    Operator op;
    AST right;

    ComparisonNode(AST l, Operator o, AST r)
        : left(move(l)), op(o), right(move(r)) {}

    bool evaluate() override
    {
        auto getVal = [](const AST& node) -> int
        {
            if (auto val = dynamic_pointer_cast<ValueNode>(node)) return val->getValue();
            if (auto fn = dynamic_pointer_cast<FuncNode>(node)) return fn->getValue();
            throw runtime_error("Invalid comparison operand");
        };
        int lhs = getVal(left);
        int rhs = getVal(right);
        switch (op)
        {
        case Operator::EQ:
            return lhs == rhs;
        case Operator::NEQ:
            return lhs != rhs;
        case Operator::GT:
            return lhs > rhs;
        case Operator::LT:
            return lhs < rhs;
        case Operator::GTE:
            return lhs >= rhs;
        case Operator::LTE:
            return lhs <= rhs;
        }
        return false;
    }
};

// === Tokenizer definitions ===

/** Token types used by the parser */
enum TokenType
{
    TOKEN_AND, TOKEN_OR, TOKEN_NOT,
    TOKEN_LPAREN, TOKEN_RPAREN, TOKEN_FUNC,
    TOKEN_EQ, TOKEN_NEQ, TOKEN_GT, TOKEN_LT, TOKEN_GTE, TOKEN_LTE,
    TOKEN_NUM, TOKEN_END
};

/** Represents a lexical token */
struct Token
{
    TokenType type;
    string value;
};

/**
 * @brief Tokenize an input expression into a vector of Tokens
 * @param input The string expression
 * @return Vector of tokens
 */
 vector<Token> tokenize(const string& input) {
    vector<Token> tokens;
    size_t i = 0;

    while (i < input.size()) {
        if (isspace(input[i])) {
            ++i;
            continue;
        }

        if (input[i] == '(') {
            tokens.push_back({TOKEN_LPAREN, "("});
            ++i;
        } else if (input[i] == ')') {
            tokens.push_back({TOKEN_RPAREN, ")"});
            ++i;
        } else if (input[i] == '!') {
            if (i + 1 < input.size() && input[i + 1] == '=') {
                tokens.push_back({TOKEN_NEQ, "!="});
                i += 2;
            } else {
                tokens.push_back({TOKEN_NOT, "!"});
                ++i;
            }
        } else if (input[i] == '=' && i + 1 < input.size() && input[i + 1] == '=') {
            tokens.push_back({TOKEN_EQ, "=="});
            i += 2;
        } else if (input[i] == '>' && i + 1 < input.size() && input[i + 1] == '=') {
            tokens.push_back({TOKEN_GTE, ">="});
            i += 2;
        } else if (input[i] == '<' && i + 1 < input.size() && input[i + 1] == '=') {
            tokens.push_back({TOKEN_LTE, "<="});
            i += 2;
        } else if (input[i] == '>') {
            tokens.push_back({TOKEN_GT, ">"});
            ++i;
        } else if (input[i] == '<') {
            tokens.push_back({TOKEN_LT, "<"});
            ++i;
        } else if (isdigit(input[i])) {
            size_t j = i;
            while (j < input.size() && isdigit(input[j])) ++j;
            tokens.push_back({TOKEN_NUM, input.substr(i, j - i)});
            i = j;
        } else if (isalpha(input[i]) || input[i] == '_') {
            // Read identifier
            size_t j = i;
            while (j < input.size() && (isalnum(input[j]) || input[j] == '_')) ++j;
            string name = input.substr(i, j - i);

            // Check for function call
            size_t k = j;
            if (k < input.size() && input[k] == '(') {
                int depth = 1;
                ++k;
                while (k < input.size() && depth > 0) {
                    if (input[k] == '(') ++depth;
                    else if (input[k] == ')') --depth;
                    ++k;
                }
                if (depth == 0) {
                    tokens.push_back({TOKEN_FUNC, input.substr(i, k - i)});
                    i = k;
                    continue;
                } else {
                    throw runtime_error("Unclosed function call parentheses at position " + to_string(i));
                }
            }

            // Not a function call, treat as keyword
            if (name == "AND") tokens.push_back({TOKEN_AND, name});
            else if (name == "OR") tokens.push_back({TOKEN_OR, name});
            else throw runtime_error("Unexpected identifier: " + name);

            i = j;
        } else {
            throw runtime_error("Unknown character: " + string(1, input[i]));
        }
    }

    tokens.push_back({TOKEN_END, ""});
    return tokens;
}
//prior tokenize, made mistakes on parenthesis matching
/*
vector<Token> tokenize(const string& input)
{
    vector<Token> tokens;
    size_t i = 0;
    while (i < input.size())
    {
        if (isspace(input[i]))
        {
            ++i;
            continue;
        }

        if (input[i] == '(') tokens.push_back({TOKEN_LPAREN, "("}), ++i;
        else if (input[i] == ')') tokens.push_back({TOKEN_RPAREN, ")" }), ++i;
        else if (input[i] == '!')
        {
            if (i + 1 < input.size() && input[i + 1] == '=')
            {
                tokens.push_back({TOKEN_NEQ, "!="});
                i += 2;
            }
            else tokens.push_back({TOKEN_NOT, "!"}), ++i;
        }
        else if (input[i] == '=')
        {
            if (i + 1 < input.size() && input[i + 1] == '=')
            {
                tokens.push_back({TOKEN_EQ, "=="});
                i += 2;
            }
            else throw runtime_error("Expected '=='");
        }
        else if (input[i] == '>')
        {
            if (i + 1 < input.size() && input[i + 1] == '=')
            {
                tokens.push_back({TOKEN_GTE, ">="});
                i += 2;
            }
            else tokens.push_back({TOKEN_GT, ">"}), ++i;
        }
        else if (input[i] == '<')
        {
            if (i + 1 < input.size() && input[i + 1] == '=')
            {
                tokens.push_back({TOKEN_LTE, "<="});
                i += 2;
            }
            else tokens.push_back({TOKEN_LT, "<"}), ++i;
        }
        else if (isdigit(input[i]))
        {
            size_t j = i;
            while (j < input.size() && isdigit(input[j])) ++j;
            tokens.push_back({TOKEN_NUM, input.substr(i, j - i)});
            i = j;
        }
        else if (isalpha(input[i]))
        {
            size_t j = i;
            while (j < input.size() && (isalnum(input[j]) || input[j] == '_')) ++j;
            string word = input.substr(i, j - i);
            if (word == "AND") tokens.push_back({TOKEN_AND, "AND"});
            else if (word == "OR") tokens.push_back({TOKEN_OR, "OR"});
            else
            {
                if (j < input.size() && input[j] == '(')
                {
                    size_t k = j;
                    int parens = 1;
                    while (++k < input.size() && parens > 0)
                    {
                        if (input[k] == '(') ++parens;
                        else if (input[k] == ')') --parens;
                    }
                    tokens.push_back({TOKEN_FUNC, input.substr(i, k - i + 1)});
                    i = k + 1;
                    continue;
                }
                else throw runtime_error("Unknown identifier: " + word);
            }
            i = j;
        }
        else throw runtime_error("Unexpected character: " + string(1, input[i]));
    }
    tokens.push_back({TOKEN_END, ""});
    return tokens;
}
*/

// ===== Parser =====
class Parser
{
    const vector<Token>& tokens;
    size_t pos = 0;

    Token peek() const
    {
        return tokens[pos];
    }
    Token advance()
    {
        return tokens[pos++];
    }

    AST parseExpr()
    {
        AST node = parseFactor();
        while (peek().type == TOKEN_OR)
        {
            advance();
            node = make_shared<OrNode>(node, parseFactor());
        }
        return node;
    }
    //AST parseComparison();
    //AST parsePrimary();

    AST parseFunc(const string& ftext)
    {
        size_t lparen = ftext.find('(');
        string name = ftext.substr(0, lparen);
        string argsText = ftext.substr(lparen + 1, ftext.size() - lparen - 2);
        vector<int> args;
        stringstream ss(argsText);
        string val;
        while (getline(ss, val, ','))
        {
            if (!val.empty() )
            {
                if (val != ")") // handle case where fn() is used
                {
                    args.push_back(stoi(val));
                }
            }
        }
        return make_shared<FuncNode>(name, args);
    }

    /**
    * @class Parser
    * @brief Parses tokens into an Abstract Syntax Tree (AST)
    */
    AST parseFactor()
    {
        AST node = parseComparison();
        while (peek().type == TOKEN_AND)
        {
            advance();
            node = make_shared<AndNode>(node, parseComparison());
        }
        return node;
    }



    AST parseComparison()
    {
        AST left = parsePrimary();
        TokenType ttype = peek().type;
        if (ttype >= TOKEN_EQ && ttype <= TOKEN_LTE)
        {
            Token t = advance();
            AST right = parsePrimary();
            using Op = ComparisonNode::Operator;
            Op op = Op::EQ;
            if (t.type == TOKEN_EQ) op = Op::EQ;
            else if (t.type == TOKEN_NEQ) op = Op::NEQ;
            else if (t.type == TOKEN_GT) op = Op::GT;
            else if (t.type == TOKEN_LT) op = Op::LT;
            else if (t.type == TOKEN_GTE) op = Op::GTE;
            else if (t.type == TOKEN_LTE) op = Op::LTE;
            return make_shared<ComparisonNode>(left, op, right);
        }
        return left;
    }
    AST parsePrimary()
    {
        Token t = advance();
        if (t.type == TOKEN_NOT)
        {
            return make_shared<NotNode>(parsePrimary());
        }
        else if (t.type == TOKEN_LPAREN)
        {
            AST expr = parseExpr();
            if (peek().type != TOKEN_RPAREN) throw runtime_error("Expected ')'");
            advance(); // consume ')'
            return expr;
        }
        else if (t.type == TOKEN_FUNC)
        {
            return parseFunc(t.value);
        }
        else if (t.type == TOKEN_NUM)
        {
            return make_shared<ValueNode>(stoi(t.value));
        }
        throw runtime_error("Unexpected token: " + t.value);
    }

public:
    explicit Parser(const vector<Token>& t) : tokens(t) {}
    AST parse()
    {
        AST result = parseExpr();
        if (peek().type != TOKEN_END)
        {
            throw runtime_error("Unexpected token after end of expression");
        }
        return result;
    }
};

// ===== Main Function =====
int main()
{
    vector<string> testInputs =
    {
/*        "isEven(4)",                             // true
        "isEven(5)",                             // false
        "!isPositive(-3)",                       // true
        "alwaysTrue() AND alwaysFalse()",        // false
        "alwaysTrue() OR alwaysFalse()",         // true
        "(fn1(5) == 5) AND (fn2(3) < 10)",        // true
        "fn3() > 7 AND !isEven(3)",              // true
        "fn3() >= 9 AND (isPositive(1) OR isEven(1))",  // true
        "(fn3() >= 9) AND (isPositive(1) OR isEven(1))",  // true
        "((fn1(1) == 1) AND ((fn2(2) < 10) OR (!(fn3() < 5))))", //true
        "((fn1(1) == 1) AND (fn2(2) < 10) OR (!(fn3() < 5)))", //true
        "(fn3() == 9)", //true
        "fn3(0) > 8", // true
        "fn3() == 9", //true
        "!(fn3() == 9)", //false
        "!(fn3() == 8)", //true
        "fn3() != fn1(9) OR fn2(3) == fn1(3)", */
        "(!fn3()) == 8"  //false
    };

    for (const auto& input : testInputs)
    {
        cout << "Input: " << input << endl;
        try
        {
            auto tokens = tokenize(input);
            Parser parser(tokens);
            AST ast = parser.parse();
            bool result = ast->evaluate();
            cout << "Result: " << boolalpha << result << endl;
        }
        catch (const exception& e)
        {
            cerr << "Error: " << e.what() << endl;
        }
        cout << "-----------------------------" << endl;
    }

    return 0;
}
