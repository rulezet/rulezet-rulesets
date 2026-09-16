rule TTP_XOR_WriteProcessMemory_6263 {
  strings:
    $key_6263 = { 35 11 [2] 07 33 [2] 01 06 [2] 2f 06 [2] 10 1a }

  condition:
    any of them
}