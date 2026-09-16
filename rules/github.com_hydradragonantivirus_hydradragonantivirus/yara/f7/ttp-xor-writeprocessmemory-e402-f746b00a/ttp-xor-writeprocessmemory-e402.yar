rule TTP_XOR_WriteProcessMemory_e402 {
  strings:
    $key_e402 = { b3 70 [2] 81 52 [2] 87 67 [2] a9 67 [2] 96 7b }

  condition:
    any of them
}