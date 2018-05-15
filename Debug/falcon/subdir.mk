################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../falcon/crypto_stream.c \
../falcon/falcon-enc.c \
../falcon/falcon-fft.c \
../falcon/falcon-keygen.c \
../falcon/falcon-sign.c \
../falcon/falcon-vrfy.c \
../falcon/frng.c \
../falcon/nist.c \
../falcon/shake.c 

OBJS += \
./falcon/crypto_stream.o \
./falcon/falcon-enc.o \
./falcon/falcon-fft.o \
./falcon/falcon-keygen.o \
./falcon/falcon-sign.o \
./falcon/falcon-vrfy.o \
./falcon/frng.o \
./falcon/nist.o \
./falcon/shake.o 

C_DEPS += \
./falcon/crypto_stream.d \
./falcon/falcon-enc.d \
./falcon/falcon-fft.d \
./falcon/falcon-keygen.d \
./falcon/falcon-sign.d \
./falcon/falcon-vrfy.d \
./falcon/frng.d \
./falcon/nist.d \
./falcon/shake.d 


# Each subdirectory must supply rules for building sources it contributes
falcon/%.o: ../falcon/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


