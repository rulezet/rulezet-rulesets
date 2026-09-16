rule TTP_XOR_WriteProcessMemory_3673 {
  strings:
    $key_3673 = { 61 01 [2] 53 23 [2] 55 16 [2] 7b 16 [2] 44 0a }

  condition:
    any of them
}