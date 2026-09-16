rule TTP_XOR_WriteProcessMemory_fa26 {
  strings:
    $key_fa26 = { ad 54 [2] 9f 76 [2] 99 43 [2] b7 43 [2] 88 5f }

  condition:
    any of them
}