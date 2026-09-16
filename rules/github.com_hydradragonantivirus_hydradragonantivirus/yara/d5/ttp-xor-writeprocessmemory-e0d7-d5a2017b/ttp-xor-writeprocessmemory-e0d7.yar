rule TTP_XOR_WriteProcessMemory_e0d7 {
  strings:
    $key_e0d7 = { b7 a5 [2] 85 87 [2] 83 b2 [2] ad b2 [2] 92 ae }

  condition:
    any of them
}