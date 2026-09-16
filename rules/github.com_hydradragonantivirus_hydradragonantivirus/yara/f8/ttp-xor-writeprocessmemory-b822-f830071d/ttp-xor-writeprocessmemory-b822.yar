rule TTP_XOR_WriteProcessMemory_b822 {
  strings:
    $key_b822 = { ef 50 [2] dd 72 [2] db 47 [2] f5 47 [2] ca 5b }

  condition:
    any of them
}