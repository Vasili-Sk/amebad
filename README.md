amebad RTL8720D sdk-amebad_v6.2b_rc 
Seeed SDK copy

GCC compile time optimized for Ryzen 7 from ~6min to 1.5 min, but since this whole project is a big fucking mess i gave up on it. 
It needs OCD scripts, but i was able to use only one MCU core, prob. you could try to do something like that: 

# A5
target create $_TARGETNAME0 cortex_a -endian $_ENDIAN -chain-position $_CHIPNAME.dap -coreid 0 -dbgbase 0xf4310000
# R5
target create $_TARGETNAME1 cortex_a -endian $_ENDIAN -chain-position $_CHIPNAME.dap -coreid 1 -dbgbase 0xf4320000

read  ROM table with command dap info and paste base addresses above

Let it collect some dust here. RIP
