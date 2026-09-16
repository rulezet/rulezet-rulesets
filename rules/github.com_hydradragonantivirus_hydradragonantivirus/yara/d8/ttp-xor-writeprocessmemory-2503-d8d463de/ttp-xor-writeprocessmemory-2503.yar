rule TTP_XOR_WriteProcessMemory_2503 {
  strings:
    $key_2503 = { 72 71 [2] 40 53 [2] 46 66 [2] 68 66 [2] 57 7a }

  condition:
    any of them
}