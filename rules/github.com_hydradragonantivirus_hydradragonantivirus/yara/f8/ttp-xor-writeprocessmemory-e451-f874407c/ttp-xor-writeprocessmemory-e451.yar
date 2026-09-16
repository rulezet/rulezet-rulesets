rule TTP_XOR_WriteProcessMemory_e451 {
  strings:
    $key_e451 = { b3 23 [2] 81 01 [2] 87 34 [2] a9 34 [2] 96 28 }

  condition:
    any of them
}