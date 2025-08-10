#ifndef __pcap_abbv_parser_h__
#define __pcap_abbv_parser_h__

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <functional>
#include <sstream>
#include <cctype>
#include <stdexcept>

namespace pcapabvparser
{
using namespace std;


/** Type definition for callable functions in expressions */
using Func = function<int(vector<int>)>;


//map<string, Func> functionRegistry;
// Preprocess, grab protocol function calls that are valid

//parse functions for protocol fn_proto #_functionName, eg fn_tcp:synFound , which calls TCP (protocol 6), layer of the stack and testd
class TcpTest
{

};



/** Registered functions that can be invoked in expressions */
map<string, Func> functionRegistry  =
{
    /*
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
    }, */
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
class ASTNode
{
public:
    /** Evaluate the node and return boolean result */
    virtual bool evaluate() = 0;
    virtual ~ASTNode() = default;

};

using AST = shared_ptr<ASTNode>;

/** Represents a numeric constant value */
class ValueNode : public ASTNode
{
    int m_value;
    ValueNode() {};

public:
    explicit ValueNode(int v) : m_value(v) {}
    bool evaluate() override
    {
        return m_value != 0;
    }
    int getValue() const
    {
        return m_value;
    }
};

/** Represents a function call */
class FuncNode : public ASTNode
{
    string m_name;
    vector<int> m_args;
public:
    FuncNode(string n, vector<int> a) : m_name(move(n)), m_args(move(a)) {}
    bool evaluate() override
    {
        return functionRegistry[m_name](m_args) != 0;
    }
    int getValue() const
    {
        return functionRegistry[m_name](m_args);
    }
};

/** Logical NOT */
class NotNode : public ASTNode
{
    AST m_child;
public:
    explicit NotNode(AST c) : m_child(move(c)) {}
    bool evaluate() override
    {
        return !m_child->evaluate();
    }
};

/** Logical AND */
class AndNode : public ASTNode
{
    AST m_left, m_right;
public:
    AndNode(AST l, AST r) : m_left(move(l)), m_right(move(r)) {}
    bool evaluate() override
    {
        return m_left->evaluate() && m_right->evaluate();
    }
};

/** Logical OR */
class OrNode : public ASTNode
{
    AST m_left, m_right;
public:
    OrNode(AST l, AST r) : m_left(move(l)), m_right(move(r)) {}
    bool evaluate() override
    {
        return m_left->evaluate() || m_right->evaluate();
    }
};

/** Comparison operations */
class ComparisonNode : public ASTNode
{
public:
    enum class Operator { EQ, NEQ, GT, LT, GTE, LTE };

private:
    AST m_left;
    Operator m_op;
    AST m_right;

public:

    ComparisonNode(AST l, Operator o, AST r)
        : m_left(move(l)), m_op(o), m_right(move(r)) {}

    bool evaluate() override
    {
        auto getVal = [](const AST& node) -> int
        {
            if (auto val = dynamic_pointer_cast<ValueNode>(node)) return val->getValue();
            if (auto fn = dynamic_pointer_cast<FuncNode>(node)) return fn->getValue();
            // NEW: also allow wrapped logical expressions to resolve to bool -> int
            return node->evaluate() ? 1 : 0;
            //throw runtime_error("Invalid comparison operand"); Unsure if we wish to compare boolean (true/false) to ints (true=1, false=0)
        };
        int lhs = getVal(m_left);
        int rhs = getVal(m_right);
        switch (m_op)
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
vector<Token> tokenize(const string& input)
{
    vector<Token> m_tokens;
    size_t i = 0;

    while (i < input.size())
    {
        if (isspace(input[i]))
        {
            ++i;
            continue;
        }

        if (input[i] == '(')
        {
            m_tokens.push_back({TOKEN_LPAREN, "("});
            ++i;
        }
        else if (input[i] == ')')
        {
            m_tokens.push_back({TOKEN_RPAREN, ")"});
            ++i;
        }
        else if (input[i] == '!')
        {
            if (i + 1 < input.size() && input[i + 1] == '=')
            {
                m_tokens.push_back({TOKEN_NEQ, "!="});
                i += 2;
            }
            else
            {
                m_tokens.push_back({TOKEN_NOT, "!"});
                ++i;
            }
        }
        else if (input[i] == '=' && i + 1 < input.size() && input[i + 1] == '=')
        {
            m_tokens.push_back({TOKEN_EQ, "=="});
            i += 2;
        }
        else if (input[i] == '>' && i + 1 < input.size() && input[i + 1] == '=')
        {
            m_tokens.push_back({TOKEN_GTE, ">="});
            i += 2;
        }
        else if (input[i] == '<' && i + 1 < input.size() && input[i + 1] == '=')
        {
            m_tokens.push_back({TOKEN_LTE, "<="});
            i += 2;
        }
        else if (input[i] == '>')
        {
            m_tokens.push_back({TOKEN_GT, ">"});
            ++i;
        }
        else if (input[i] == '<')
        {
            m_tokens.push_back({TOKEN_LT, "<"});
            ++i;
        }
        else if (isdigit(input[i]))
        {
            size_t j = i;
            while (j < input.size() && isdigit(input[j])) ++j;
            m_tokens.push_back({TOKEN_NUM, input.substr(i, j - i)});
            i = j;
        }
        else if (isalpha(input[i]) || input[i] == '_')
        {
            // Read identifier
            size_t j = i;
            while (j < input.size() && (isalnum(input[j]) || input[j] == '_')) ++j;
            string name = input.substr(i, j - i);

            // Check for function call
            size_t k = j;
            if (k < input.size() && input[k] == '(')
            {
                int depth = 1;
                ++k;
                while (k < input.size() && depth > 0)
                {
                    if (input[k] == '(') ++depth;
                    else if (input[k] == ')') --depth;
                    ++k;
                }
                if (depth == 0)
                {
                    m_tokens.push_back({TOKEN_FUNC, input.substr(i, k - i)});
                    i = k;
                    continue;
                }
                else
                {
                    throw runtime_error("Unclosed function call parentheses at position " + to_string(i));
                }
            }

            // Not a function call, treat as keyword
            if (name == "AND") m_tokens.push_back({TOKEN_AND, name});
            else if (name == "OR") m_tokens.push_back({TOKEN_OR, name});
            else throw runtime_error("Unexpected identifier: " + name);

            i = j;
        }
        else
        {
            throw runtime_error("Unknown character: " + string(1, input[i]));
        }
    }

    m_tokens.push_back({TOKEN_END, ""});
    return m_tokens;
}


// ===== Parser =====
class Parser
{
    const vector<Token>& m_tokens;
    size_t m_pos = 0;

public:
    Token peek() const
    {
        return m_tokens[m_pos];
    }
    Token advance()
    {
        return m_tokens[m_pos++];
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
    explicit Parser(const vector<Token>& t) : m_tokens(t) {}
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
} //end of namespace
#endif // __pcap_abbv_parser_h__


