// 2023 - created by Mehmet Cagri Aksoy
// github.com/mcagriaksoy

// Compile: g++ main.cpp -L/usr/local/lib/ -lssl -lcrypto -lCppUTest -lCppUTestExt -o main

#include "CppUTest/CommandLineTestRunner.h"

int main(int ac, char** av)
{
   return CommandLineTestRunner::RunAllTests(ac, av);
}