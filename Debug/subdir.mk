################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../raptor.c \
../linkable_raptor.c \
../poly.c \
../print.c \
../test.c 

OBJS += \
./raptor.o \
../linkable_raptor.o \
./poly.o \
./print.o \
./test.o 

C_DEPS += \
./raptor.d \
../linkable_raptor.d \
./poly.d \
./print.d \
./test.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


