rule TTP_XOR_WriteProcessMemory_e031 {
  strings:
    $key_e031 = { b7 43 [2] 85 61 [2] 83 54 [2] ad 54 [2] 92 48 }

  condition:
    any of them
}