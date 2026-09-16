rule TTP_XOR_WriteProcessMemory_e051 {
  strings:
    $key_e051 = { b7 23 [2] 85 01 [2] 83 34 [2] ad 34 [2] 92 28 }

  condition:
    any of them
}