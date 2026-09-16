rule TTP_XOR_WriteProcessMemory_7123 {
  strings:
    $key_7123 = { 26 51 [2] 14 73 [2] 12 46 [2] 3c 46 [2] 03 5a }

  condition:
    any of them
}