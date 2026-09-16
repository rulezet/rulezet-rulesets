rule TTP_XOR_WriteProcessMemory_feba {
  strings:
    $key_feba = { a9 c8 [2] 9b ea [2] 9d df [2] b3 df [2] 8c c3 }

  condition:
    any of them
}