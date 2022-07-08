# Deadroot
A simple privilege escalation rootkit.

## Interaction with rootkit
Send signal **63** to any pid (kill -63 0) for hidding/showing the kernel module.    
Send signal **64** to any pid for getting (kill -64 0) root

## Loading and removing the module
Loading -> ```insmod deadroot.ko```    
Removing -> ```rmmod deadroot```

## Compiling
First make sure you have installed the linux headers for your kernel.    
Then, in the project folder run ```make```. It should leave you with **deadroot.ko**

## Inspired by
[xcellerator](https://github.com/xcellerator) -> finding kallsyms_lookup_name address and some of his examples.    
[jm33_ng](https://jm33.me/) -> overwriting cr0 permissions.    
