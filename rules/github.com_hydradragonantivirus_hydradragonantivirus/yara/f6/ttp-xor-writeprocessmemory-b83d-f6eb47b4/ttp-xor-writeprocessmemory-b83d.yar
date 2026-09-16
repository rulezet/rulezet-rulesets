rule TTP_XOR_WriteProcessMemory_b83d {
  strings:
    $key_b83d = { ef 4f [2] dd 6d [2] db 58 [2] f5 58 [2] ca 44 }

  condition:
    any of them
}