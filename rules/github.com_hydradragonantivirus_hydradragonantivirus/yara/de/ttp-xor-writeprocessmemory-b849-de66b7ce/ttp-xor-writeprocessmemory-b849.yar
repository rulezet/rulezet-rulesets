rule TTP_XOR_WriteProcessMemory_b849 {
  strings:
    $key_b849 = { ef 3b [2] dd 19 [2] db 2c [2] f5 2c [2] ca 30 }

  condition:
    any of them
}