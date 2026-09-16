rule TTP_XOR_WriteProcessMemory_5460 {
  strings:
    $key_5460 = { 03 12 [2] 31 30 [2] 37 05 [2] 19 05 [2] 26 19 }

  condition:
    any of them
}