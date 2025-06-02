
//strip out whitespace
std::string filter ="(A OR B OR C) AND ((D AND E OR C) OR (F OR Q))";
s.erase(std::remove_if(s.begin(), s.end(),
                            [](char c) {
                                return (c == ' ' || c == '\n' || c == '\r' ||
                                        c == '\t' || c == '\v' || c == '\f');
                            }),
                            s.end());



//(A OR B OR C) AND ((D AND E OR C) OR (F OR Q))

(A or B or C) = ans1 = ((A or B) or C)

(D and E or C) = ans2 = (D and E) or C)

(F or Q ) = ans3

ans1 and (ans 2 OR ans 3)
(ans2 or ans3) = and4

ans1 and ans4

Replace first parens, assign to proxyToken


Take complete parens
if more than 2 params, parse left ot right

map A,b,c,d,e,f,q to data variables (bool)

=======

SYN_count5 = syn_count >=5


Syntax for 'of interest', syntax for 'capture/save'



class ProtocolEval {


};
