rule TTP_XOR_WriteProcessMemory_02e9 {
  strings:
    $key_02e9 = { 55 9b [2] 67 b9 [2] 61 8c [2] 4f 8c [2] 70 90 }

  condition:
    any of them
}