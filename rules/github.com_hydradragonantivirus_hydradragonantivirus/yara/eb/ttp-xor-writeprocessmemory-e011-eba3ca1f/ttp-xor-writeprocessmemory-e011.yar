rule TTP_XOR_WriteProcessMemory_e011 {
  strings:
    $key_e011 = { b7 63 [2] 85 41 [2] 83 74 [2] ad 74 [2] 92 68 }

  condition:
    any of them
}