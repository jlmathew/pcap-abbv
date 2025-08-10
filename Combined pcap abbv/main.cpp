#include <iostream>
#include "parser.h"

using namespace std;
using namespace pcapabvparser;

// ===== Main Function =====
int main()
{
    vector<string> testInputs =
    {
        "isEven(4)",                             // true
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
        "fn3() != fn1(9) OR fn2(3) == fn1(3)",
        "(!fn3()) == 8",  //false
        "(((fn3())) == 8)" //false
    };

    //example on adding function registerys (should be via object funct call
    pcapabvparser::functionRegistry["fn1"] = [](vector<int> args)
    {
        return args.empty() ? 0 : args[0];
    };
    pcapabvparser::functionRegistry["fn2"] = [](vector<int> args)
    {
        return args.empty() ? 0 : args[0];
    };

    pcapabvparser::functionRegistry["fn3"]= [](vector<int>)
    {
        return 9;
    };


    for (const auto& input : testInputs)
    {
        cout << "Input: " << input << endl;
        try
        {
            auto tokens = tokenize(input);
            Parser parser(tokens);
            AST ast = parser.parse();
            AST ast2 = ast; // make a copy
            bool result = ast->evaluate();
            cout << "Result : " << boolalpha << result << endl;
            cout << "Result2: " << std::boolalpha << ast2->evaluate() << endl;
        }
        catch (const exception& e)
        {
            cerr << "Tokenize Error: " << e.what() << endl;
        }
        cout << "-----------------------------" << endl;
    }

    return 0;
}

