rule TTP_XOR_WriteProcessMemory_e004 {
  strings:
    $key_e004 = { b7 76 [2] 85 54 [2] 83 61 [2] ad 61 [2] 92 7d }

  condition:
    any of them
}