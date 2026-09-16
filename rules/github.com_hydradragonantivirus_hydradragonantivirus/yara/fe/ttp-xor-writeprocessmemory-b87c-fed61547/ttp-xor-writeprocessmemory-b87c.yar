rule TTP_XOR_WriteProcessMemory_b87c {
  strings:
    $key_b87c = { ef 0e [2] dd 2c [2] db 19 [2] f5 19 [2] ca 05 }

  condition:
    any of them
}