rule TTP_XOR_WriteProcessMemory_e021 {
  strings:
    $key_e021 = { b7 53 [2] 85 71 [2] 83 44 [2] ad 44 [2] 92 58 }

  condition:
    any of them
}