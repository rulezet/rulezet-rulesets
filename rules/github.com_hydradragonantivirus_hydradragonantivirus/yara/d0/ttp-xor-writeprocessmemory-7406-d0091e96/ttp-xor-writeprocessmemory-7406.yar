rule TTP_XOR_WriteProcessMemory_7406 {
  strings:
    $key_7406 = { 23 74 [2] 11 56 [2] 17 63 [2] 39 63 [2] 06 7f }

  condition:
    any of them
}