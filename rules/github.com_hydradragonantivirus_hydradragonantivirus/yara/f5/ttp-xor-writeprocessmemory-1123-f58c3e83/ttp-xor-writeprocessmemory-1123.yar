rule TTP_XOR_WriteProcessMemory_1123 {
  strings:
    $key_1123 = { 46 51 [2] 74 73 [2] 72 46 [2] 5c 46 [2] 63 5a }

  condition:
    any of them
}