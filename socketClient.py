#!/usr/bin/env python3

import socket
import ssl
import argparse
import sys

""" Set of Constant fields to use in code """
# Class and semester number
COURSE = 'cs5700spring2022'

""" The "message" field in the client request
1. HELLO     2. EVAL
3. STATUS    4. ERR """
MSG_HELLO = 'HELLO'
MSG_EVAL = 'EVAL'
MSG_STATUS = 'STATUS'
MSG_ERROR = 'ERR'
MSG_BYE = 'BYE'

# Predefined DivideByZero error code
ERRMESSAGE = '#DIV/0'

# MAX Message length from server
MAX_MSG_LENGTH = 16384
# Message decode format
FORMAT = 'utf-8'

# The EVAL/BYE message from the server;
global evalMessage


""" Helper method to check if expression is an operator """
def isOperator(exp):
    return (exp == '+' or exp == '-' or exp == '*' or exp == '//' or exp == '<<^')

""" Helper function to receive complete messages from server """
def receiveMessage(socket):
    packetsTotal = ""
    while True:
        packetIncoming = socket.recv(MAX_MSG_LENGTH).decode(FORMAT)
        packetsTotal += packetIncoming
        if "\n" in packetsTotal: # Incoming packet has finished
            break

    return packetsTotal

""" Expression Evaluation
RULES of EVALUATION:
    1. If the variable is an opening parentheses "(" or an operator, add to the stack of operators
    2. If the variable is a closing parentheses ")", pop operators and operands from stack until the expression between the parentheses is evaluated. 
        Add the result to the operand stack and pop the opening parentheses

    4. If the variable is an Integer, add to the operands stack.
    5. Pop the last variable from the stack which is the result
"""
def evaluationResult(expression):
    if (len(expression) == 0):
        return 0
    
    # FLAG variable to detect error in evaluation
    hasError = False
    operandsStack = []
    operatorStack = []

    # Refer steps 1 through 4
    for exp in expression:
        if (exp == '(' or isOperator(exp)):
            operatorStack.append(exp)
            
        elif (exp == ')'):
            while (len(operatorStack) != 0 and operatorStack[-1] != '('):
                value2 = operandsStack.pop()
                value1 = operandsStack.pop()
                operator = operatorStack.pop()

                evalResult, hasError = evaluation(value1, value2, operator)
                if hasError: return evalResult, hasError
                operandsStack.append(evalResult)
                operatorStack.pop()
        
        elif (exp.lstrip('-').isdigit()):
            operandsStack.append(int(exp))

    # Refer step 5
    return operandsStack[-1], hasError

""" Value evaluation method 
        1. @params: Value 1, Value 2 and an operator
        2. @return: The evaluation result and FLAG to detect if DivBy0 error has occurred """
def evaluation(value1, value2, operator):
    hasError = False
    evaluationResult = 0

    try:
        if (operator == '+'): evaluationResult = value1 + value2
        
        elif (operator == '-'): evaluationResult = value1 - value2

        elif (operator == '*'): evaluationResult = value1 * value2
        
        elif (operator == '//'): evaluationResult = value1 // value2
        
        elif (operator == '<<^'): evaluationResult = (value1 << 13) ^ value2

    except:
        # DivBy0 error
        hasError = True
        
    return evaluationResult, hasError

""" Helper to check validity of server input expression - EVAL or BYE """
def isValidExpression(message, flag):
    if (len(message) == 0 or len(flag) == 0): 
        return False
    
    exp = message.split()
    if (len(exp) < 2 or not (exp[0] == COURSE)):
        return False
    
    if flag == MSG_EVAL:
        return (exp[1] == MSG_EVAL)
    
    return (exp[1] == MSG_BYE)

""" Helper function to Close Socket """
def closeStream(socket):
    socket.close()

""" Main function: 
        1. Create Secure Socket
        2. Make connection with server and send the HELLO message
        3. Receive EVAL messages and evaluate until: 
            a. We receive a DivisionByZero error
            b. The input EVAL expression is invalid
        4. Send the BYE message and receive the 64-byte secret flag
"""
def main(hostname, port, neuID):
    try:
        # Set up Socket
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Wrap Socket in SSL format, based on script input
        # Set up Handshake to establish security attributes (cipher suite) and, a valid session to read/write application data
        clientSocketSSL = ssl.wrap_socket(clientSocket, ssl_version=ssl.PROTOCOL_SSLv23)
        addr = hostname, port
        clientSocketSSL.connect(addr)   # Connect with socket
    except:
        # Can't connect with socket
        closeStream(clientSocketSSL)
        sys.exit("Can't connect with socket!" + "\n")

    # Send HELLO message to the server
    # Confirm whether output stream has not encountered any errors
    try: 
        helloMessage = COURSE + " " + MSG_HELLO + " " + neuID + "\n"
        clientSocketSSL.send(helloMessage.encode(FORMAT))
    except:
        # IO Exception with socket stream
        closeStream()
        sys.exit("IO Exception with socket stream" + "\n")

    # Receive EVAL messages from the server and send the evaluation as output
    # Receive FIRST EVAL message
    evalMessage = receiveMessage(clientSocketSSL)

    while ((MSG_EVAL in evalMessage) and isValidExpression(evalMessage, MSG_EVAL)):
        hasError = False
        expression = evalMessage.split()
        range = expression[2 : ]
        result, hasError = evaluationResult(range)

        # If error is found, send ERR message to server
        if hasError:
            errorMessage = COURSE + " " + MSG_ERROR + " " + ERRMESSAGE + "\n"
            clientSocketSSL.send(errorMessage.encode(FORMAT))
            # Reset error
            hasError = False

        # Send STATUS message with the evaluation result
        else:
            statusMessage = COURSE + " " + MSG_STATUS + " " + str(result) + "\n"
            clientSocketSSL.send(statusMessage.encode(FORMAT))

        # Read next EVAL messages
        evalMessage = receiveMessage(clientSocketSSL)

    # In case no more EVAL messages received, BYE message has been received
    if ((MSG_BYE in evalMessage) and isValidExpression(evalMessage, MSG_BYE)):
        # Print BYE message
        print (evalMessage)

    # Invalid expression received - close stream
    elif (not isValidExpression(evalMessage, "")):
        pass

    closeStream(clientSocketSSL)

""" Script argument parser """
if __name__ == "__main__":
    parser = argparse.ArgumentParser('Project 1: Simple Client')

    # Port Number: Optional argument
    parser.add_argument('-p', action='store', type=int, default=27995, dest='PORT', help='<-p port>')
    # SSL, Hostname and NEUID: Mandatory
    parser.add_argument('-s', action='store_true', dest='SSL', required=True, help='<-s>')   # Store True value as default; Required on optional tag
    parser.add_argument('HOST', action='store', type=str, help='[hostname]')    # Store value from input
    parser.add_argument('NEU_USERNAME', action='store', type=str, help='[NEU ID]')     # Store value from input

    args = parser.parse_args()
    # Pass args to main() method
    main(args.HOST, args.PORT, args.NEU_USERNAME)
