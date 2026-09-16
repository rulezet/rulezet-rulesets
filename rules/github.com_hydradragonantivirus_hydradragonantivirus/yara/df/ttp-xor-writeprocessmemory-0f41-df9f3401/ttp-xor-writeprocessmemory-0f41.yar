rule TTP_XOR_WriteProcessMemory_0f41 {
  strings:
    $key_0f41 = { 58 33 [2] 6a 11 [2] 6c 24 [2] 42 24 [2] 7d 38 }

  condition:
    any of them
}