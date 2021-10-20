#!/bin/bash

value=0

while [ 1 ]
	do
	value=$(($value+1))
	echo "The program has been running $value times so far."
	./stack
done
