rule TTP_XOR_WriteProcessMemory_fad1 {
  strings:
    $key_fad1 = { ad a3 [2] 9f 81 [2] 99 b4 [2] b7 b4 [2] 88 a8 }

  condition:
    any of them
}