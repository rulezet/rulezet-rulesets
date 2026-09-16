rule TTP_XOR_WriteProcessMemory_1a13 {
  strings:
    $key_1a13 = { 4d 61 [2] 7f 43 [2] 79 76 [2] 57 76 [2] 68 6a }

  condition:
    any of them
}