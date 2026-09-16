rule TTP_XOR_WriteProcessMemory_16e9 {
  strings:
    $key_16e9 = { 41 9b [2] 73 b9 [2] 75 8c [2] 5b 8c [2] 64 90 }

  condition:
    any of them
}