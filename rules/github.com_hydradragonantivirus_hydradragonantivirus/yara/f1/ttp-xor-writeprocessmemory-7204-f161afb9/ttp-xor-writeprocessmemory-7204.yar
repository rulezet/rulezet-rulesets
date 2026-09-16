rule TTP_XOR_WriteProcessMemory_7204 {
  strings:
    $key_7204 = { 25 76 [2] 17 54 [2] 11 61 [2] 3f 61 [2] 00 7d }

  condition:
    any of them
}