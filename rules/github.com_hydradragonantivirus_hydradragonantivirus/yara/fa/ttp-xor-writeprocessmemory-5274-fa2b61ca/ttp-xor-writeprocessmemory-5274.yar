rule TTP_XOR_WriteProcessMemory_5274 {
  strings:
    $key_5274 = { 05 06 [2] 37 24 [2] 31 11 [2] 1f 11 [2] 20 0d }

  condition:
    any of them
}