rule TTP_XOR_WriteProcessMemory_3074 {
  strings:
    $key_3074 = { 67 06 [2] 55 24 [2] 53 11 [2] 7d 11 [2] 42 0d }

  condition:
    any of them
}