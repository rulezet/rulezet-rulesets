rule TTP_XOR_WriteProcessMemory_e463 {
  strings:
    $key_e463 = { b3 11 [2] 81 33 [2] 87 06 [2] a9 06 [2] 96 1a }

  condition:
    any of them
}