rule TTP_XOR_WriteProcessMemory_0352 {
  strings:
    $key_0352 = { 54 20 [2] 66 02 [2] 60 37 [2] 4e 37 [2] 71 2b }

  condition:
    any of them
}