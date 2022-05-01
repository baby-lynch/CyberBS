#!/bin/bash

valgrind --log-file=valgrind.log  --tool=memcheck  --leak-check=full  --show-leak-kinds=all  ./main 