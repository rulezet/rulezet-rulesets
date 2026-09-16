rule TTP_XOR_WriteProcessMemory_23e9 {
  strings:
    $key_23e9 = { 74 9b [2] 46 b9 [2] 40 8c [2] 6e 8c [2] 51 90 }

  condition:
    any of them
}