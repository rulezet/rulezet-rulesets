rule TTP_XOR_WriteProcessMemory_e452 {
  strings:
    $key_e452 = { b3 20 [2] 81 02 [2] 87 37 [2] a9 37 [2] 96 2b }

  condition:
    any of them
}