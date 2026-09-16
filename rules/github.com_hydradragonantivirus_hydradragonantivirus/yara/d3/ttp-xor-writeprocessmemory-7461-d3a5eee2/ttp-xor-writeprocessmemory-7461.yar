rule TTP_XOR_WriteProcessMemory_7461 {
  strings:
    $key_7461 = { 23 13 [2] 11 31 [2] 17 04 [2] 39 04 [2] 06 18 }

  condition:
    any of them
}