rule TTP_XOR_WriteProcessMemory_e467 {
  strings:
    $key_e467 = { b3 15 [2] 81 37 [2] 87 02 [2] a9 02 [2] 96 1e }

  condition:
    any of them
}