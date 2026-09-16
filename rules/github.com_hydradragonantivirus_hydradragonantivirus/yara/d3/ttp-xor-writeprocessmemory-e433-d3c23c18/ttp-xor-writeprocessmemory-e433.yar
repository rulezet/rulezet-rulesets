rule TTP_XOR_WriteProcessMemory_e433 {
  strings:
    $key_e433 = { b3 41 [2] 81 63 [2] 87 56 [2] a9 56 [2] 96 4a }

  condition:
    any of them
}