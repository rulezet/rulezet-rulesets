rule TTP_XOR_WriteProcessMemory_bbc9 {
  strings:
    $key_bbc9 = { ec bb [2] de 99 [2] d8 ac [2] f6 ac [2] c9 b0 }

  condition:
    any of them
}