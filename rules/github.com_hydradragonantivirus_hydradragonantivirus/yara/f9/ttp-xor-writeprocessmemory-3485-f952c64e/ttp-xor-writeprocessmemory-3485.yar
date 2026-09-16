rule TTP_XOR_WriteProcessMemory_3485 {
  strings:
    $key_3485 = { 63 f7 [2] 51 d5 [2] 57 e0 [2] 79 e0 [2] 46 fc }

  condition:
    any of them
}