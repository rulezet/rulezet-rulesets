rule TTP_XOR_WriteProcessMemory_0f02 {
  strings:
    $key_0f02 = { 58 70 [2] 6a 52 [2] 6c 67 [2] 42 67 [2] 7d 7b }

  condition:
    any of them
}