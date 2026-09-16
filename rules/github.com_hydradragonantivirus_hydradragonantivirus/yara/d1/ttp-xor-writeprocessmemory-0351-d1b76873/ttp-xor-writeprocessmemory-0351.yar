rule TTP_XOR_WriteProcessMemory_0351 {
  strings:
    $key_0351 = { 54 23 [2] 66 01 [2] 60 34 [2] 4e 34 [2] 71 28 }

  condition:
    any of them
}