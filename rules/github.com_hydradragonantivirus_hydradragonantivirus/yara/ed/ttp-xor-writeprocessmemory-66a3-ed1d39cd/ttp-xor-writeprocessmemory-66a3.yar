rule TTP_XOR_WriteProcessMemory_66a3 {
  strings:
    $key_66a3 = { 31 d1 [2] 03 f3 [2] 05 c6 [2] 2b c6 [2] 14 da }

  condition:
    any of them
}