#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <vector>
#include <string>
#include <cstring>
#include <cctype>
#include <queue>
#include <stack>
#include <algorithm>

using namespace std;

int main() {
//order of precedence (),!,AND, OR, =, <>, <,>, <=, >=
    //std::string formula="( ((C AND D) OR E OR F) AND F OR C) OR (E) AND (!(!A OR B))";
    std::string formula="( ((C AND D>8) OR (E OR F=0) AND F>3 OR G OR (C OR (E) AND (!(!A OR B<>4)))))";
    stack<int> m_filoQueue;
    deque<std::string> m_precedenceFns;
    //vector<std::string> m_precedenceFns;
    int match=0;
    int index=-1;
    string registerName="PAREN_EVAL";
    std::map <string, std::string> eval;
    int evalIndex=0;
    string evalIndexStr;
    std::cout << "formula:" << formula << endl;
    char element;
    for (unsigned int loop = 0; loop < formula.length(); loop++ ) {
        index++;
        element=formula[loop];
//ignore spaces
        if (element == ' ') continue;

//match last parens
        if (element == '(') {
            m_filoQueue.push(index);
            continue;
        }

        if (element == ')') {
            match = m_filoQueue.top();
            m_filoQueue.pop();
            evalIndexStr=registerName+to_string(evalIndex++);
            eval[evalIndexStr]= formula.substr(match,index-match+1);

            m_precedenceFns.push_back(formula.substr(match+1,index-match-1));

            //cout << evalIndexStr << "--> " << eval[evalIndexStr] << "  " << m_filoQueue.size() << endl;
            formula.replace(match, index-match+1, evalIndexStr);
//formula.replace(match, loop-match+1, evalIndexStr);
            loop=match+evalIndexStr.length()-1;
//loop=match;
            index=loop;
            //cout << formula << ":" << formula.size() << ","<< loop <<endl;


        }

    }

    enum operation_type {
        NOP,
        OR,
        AND,
        INVERT,
        EQUAL,
        NOTEQUAL,
        LESSTHAN,
        MORETHAN,
        LESSEQUAL,
        MOREEQUAL
    };
    index=0;
    string fn;
    size_t matchLocationAnd, matchLocationOr, matchLocationValue, matchLocationInvert;
    string compareValue;
    string fnCall;
    vector<operation_type> orderOfOperations;
    vector<string> valuesOfOperations; //Needs struct/union, as it may be integer, Parens evaluation, or protocol function call
    vector<bool> resultsOfOperations; //this changes only, results per Parens evaluation, easier for debugging


    std::vector<string> operation_type_name {"NOP","OR","AND","!","=","<>","<",">","<=",">="};

    struct parenthesisEval {
        string originalValue;
        string name;
        unsigned int index;
        vector<string> leftArgValues;
        vector<operation_type> operations;
    } tempEval;


    while (!m_precedenceFns.empty())

        //should change to vector and iterate, not filo, easier to copy/duplicate
    {
        fn=m_precedenceFns.front();
        tempEval.index=index;
        std::cout << index << "  "  << fn << endl << endl;
        index++;
        m_precedenceFns.pop_front();
        tempEval.originalValue=fn;



//NOTE: do not use on strings for names, esp AND, OR, REG
        //check for ! (unary) then get variable
        //check for left to right, and, or (binary) (var AND var2, var1 OR var2)
        //break into individual statements funct1 (bool op) funct2 (bool op) funct3 (boolop) funct4 ...

        string leftArg;
        cout << "Fn:" << fn << endl;




        operation_type op, unaryOp, compareOp;
        do {
            matchLocationAnd= fn.find("AND") ;
            matchLocationOr= fn.find("OR") ;

            //neeed to call  functions for stack, eaxh stack per register
            //regx , one for rq op r1 op r2, other for f1 op f2 op f3 per each register
            if (matchLocationOr < matchLocationAnd) {
                leftArg=fn.substr(0,matchLocationOr);
                op=OR;
                //cout <<  leftArg << " " << op <<  " " ;
                fn=fn.substr(matchLocationOr+2);
            } else if (matchLocationAnd < matchLocationOr) {
                leftArg=fn.substr(0,matchLocationAnd);
                op=AND;
                //cout <<  leftArg << " " << op <<  " " ;
                fn=fn.substr(matchLocationAnd+3);
            } else  {
                leftArg=fn; //rightmost arguement/value
                op=NOP;
                //cout << leftArg << endl;
            }
            //remove white space

            leftArg.erase (std::remove (leftArg.begin(), leftArg.end(), ' '), leftArg.end());

            //cout << "Evaluate("<< leftArg << ")" << endl;

//need to evaluate left side for invert or comparison

            //check for !
            compareOp=NOP;
            compareValue="";
            fnCall="";

            matchLocationInvert=leftArg.find("!");
            if (matchLocationInvert==std::string::npos) {
                unaryOp=NOP;
            } else {
                unaryOp=INVERT;
                leftArg.erase(matchLocationInvert,1);
                fnCall=leftArg;
                cout << "Invert " << leftArg << endl;
            }

            //check for comparison, it could be !B>5, which will translate to !(b>5)




            //check for comparison (hardcode compare) (variable comparison value) (if var is Cnt, we need state)

            matchLocationValue= leftArg.find("<>");
            if ( (compareOp == NOP) && matchLocationValue != std::string::npos ) {
                compareOp=NOTEQUAL;
                fnCall=leftArg.substr(0,matchLocationValue);
                compareValue=leftArg.substr(matchLocationValue+2);
            }
            matchLocationValue= leftArg.find(">=");
            if ( (matchLocationValue != std::string::npos) && (compareOp == NOP)) {
                compareOp=MOREEQUAL;
                fnCall=leftArg.substr(0,matchLocationValue);
                compareValue=leftArg.substr(matchLocationValue+2);
            }
            matchLocationValue= leftArg.find(">");
            if (  (matchLocationValue != std::string::npos) && (compareOp == NOP)) {
                compareOp=MORETHAN;
                fnCall=leftArg.substr(0,matchLocationValue);
                compareValue=leftArg.substr(matchLocationValue+1);
            }

            matchLocationValue= leftArg.find("<=");
            if ( (matchLocationValue != std::string::npos) && (compareOp == NOP)) {
                compareOp=LESSEQUAL;
                fnCall=leftArg.substr(0,matchLocationValue);
                compareValue=leftArg.substr(matchLocationValue+2);
            }
            matchLocationValue= leftArg.find("<");
            if (( matchLocationValue != std::string::npos) && (compareOp == NOP)) {
                compareOp=LESSTHAN;
                fnCall=leftArg.substr(0,matchLocationValue);
                compareValue=leftArg.substr(matchLocationValue+1);
            }



            matchLocationValue= leftArg.find("=");
            if ( (matchLocationValue != std::string::npos) && (compareOp == NOP)) {
                compareOp=EQUAL;
                fnCall=leftArg.substr(0,matchLocationValue);
                compareValue=leftArg.substr(matchLocationValue+1);
            }

            // This may neeed new OPs to COVER these type of actions
            if (compareOp==NOP) {
                //Register type value or flag check
                matchLocationValue=leftArg.find(registerName);
                if (matchLocationValue != std::string::npos) {
                    cout<< "Parens " << leftArg << " found" << endl;
                } else { //assume Protocol Fn call
                    cout << "Protocol check " << leftArg << endl;

                }
//tempEval.operations.push_back(op);
 //           tempEval.leftArgValues.push_back(leftArg);
            }
            //may have NOP, each function should push
            if (compareOp!=NOP) {
                tempEval.operations.push_back(compareOp);
                tempEval.leftArgValues.push_back(fnCall);
                tempEval.leftArgValues.push_back(compareValue);
            }
            if (unaryOp!=NOP) {
                tempEval.operations.push_back(unaryOp);
                tempEval.leftArgValues.push_back(fnCall);
            }

            if (op != NOP) {
                tempEval.operations.push_back(op);
                tempEval.leftArgValues.push_back(leftArg);
            }

            //if (op == NOP) {
            //tempEval.operations.push_back(op);
            //tempEval.leftArgValues.push_back(leftArg);} //?





            std::cout << leftArg <<": " << fnCall << " " << operation_type_name[(int)compareOp] << " " <<  compareValue  << endl;
        } while (!((matchLocationAnd == std::string::npos) && (matchLocationOr == std::string::npos)));

        std::string temp="";
        int leftIndex=0;

        for (int i=0; i< tempEval.operations.size(); i++) {
            if (tempEval.operations[i]==INVERT) {
                temp+=operation_type_name[(int)INVERT]+tempEval.leftArgValues[leftIndex++];

            } else if (tempEval.operations[i]==OR)  {
                temp+=operation_type_name[(int)OR]+tempEval.leftArgValues[leftIndex++];
            } else if (tempEval.operations[i]==AND)  {
                temp+=operation_type_name[(int)AND]+tempEval.leftArgValues[leftIndex++];
            } else if (tempEval.operations[i]==NOP) {
                temp+tempEval.leftArgValues[leftIndex++];
            } else { //compare
                temp += tempEval.leftArgValues[leftIndex++]+operation_type_name[(int)tempEval.operations[i]]+tempEval.leftArgValues[leftIndex++];
            }

        }
        cout<<"Reconstituted " << tempEval.originalValue << ":" << temp << endl;
        continue;

//check for function name; (which should be mapped, protocol to fnName, eg tcp.resetSet, udp.FragSet, tcp.synCnt (pass parameter)). comparisons will need to be initialized with parameter

//so read parameter, and know how many params to read (1 or 2) (vector of operations followed by params)


//pop actions onto new stack.

    }
//left to right, push value and operand, priority is comparisons >,<,=, etc
//stack map, Rx, x is an index , so resolve R0 first, then R1, then R2, etc.
//
//replace letters with function calls, or comparisons
//push AND OR ont another function stack
//pull from function stack, read 1 (! or not) or read 2 (and, or , comparison)

//for Counting functions, mark as 'need post evaluation'
//global option to save pre 'x' packets or post 'y' number of packets will always require post evaluation
//post evaluation requires memcpy of packet, and thread to process it.


//future todo, put in error statements for erroneous parens, functions or calls

}

//design doc
//parsing options for 'packets of interest', 'packets to save' (instant save or save later), and global options
//master protocol has insight into supported protocols
//each protocol has its own evaluators and names to match
//protocl matches all for encapsulation, or protocol has a encapsualtion # to apply (eg tcp.reset:1)
//packets processed and saved when appropriate.
//pop expired pre packets, always save 'y' packets after, unless they are 'interest' and need 'y' more after


//global options
//pre 'x' packets to save
//post 'y' packets to save
//memory mapper (new vs malloc or custom pre-allocatedd memory to be used)
//how many packets/memory per stream before write (if stream is not saved, need to delete)
//how much memory maximum before forcing writes to disk
//watermark for how much memory when suggested to write to disk
//number of threads
//pcap filter to preprocess.
//status file name and update timer
//size of packet ot save (eg up to layer UDP (or second UDP), or size)
//handle encapsulated packets (prestrip which protocols), or remove TLS fields which are not useful

//custom may use MTU block metrics, or maximum packet size/layer used
//
//handle kill, cntrl C, error conditions
