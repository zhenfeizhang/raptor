################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../rng/crypto_hash_sha512.c \
../rng/fastrandombytes.c \
../rng/rng.c \
../rng/shred.c 

OBJS += \
./rng/crypto_hash_sha512.o \
./rng/fastrandombytes.o \
./rng/rng.o \
./rng/shred.o 

C_DEPS += \
./rng/crypto_hash_sha512.d \
./rng/fastrandombytes.d \
./rng/rng.d \
./rng/shred.d 


# Each subdirectory must supply rules for building sources it contributes
rng/%.o: ../rng/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


