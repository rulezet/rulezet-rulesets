rule TTP_XOR_WriteProcessMemory_b871 {
  strings:
    $key_b871 = { ef 03 [2] dd 21 [2] db 14 [2] f5 14 [2] ca 08 }

  condition:
    any of them
}