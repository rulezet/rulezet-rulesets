rule TTP_XOR_WriteProcessMemory_3003 {
  strings:
    $key_3003 = { 67 71 [2] 55 53 [2] 53 66 [2] 7d 66 [2] 42 7a }

  condition:
    any of them
}