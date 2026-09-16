rule TTP_XOR_WriteProcessMemory_0f74 {
  strings:
    $key_0f74 = { 58 06 [2] 6a 24 [2] 6c 11 [2] 42 11 [2] 7d 0d }

  condition:
    any of them
}