rule TTP_XOR_WriteProcessMemory_6311 {
  strings:
    $key_6311 = { 34 63 [2] 06 41 [2] 00 74 [2] 2e 74 [2] 11 68 }

  condition:
    any of them
}