rule TTP_XOR_WriteProcessMemory_3473 {
  strings:
    $key_3473 = { 63 01 [2] 51 23 [2] 57 16 [2] 79 16 [2] 46 0a }

  condition:
    any of them
}