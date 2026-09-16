rule TTP_XOR_WriteProcessMemory_2a65 {
  strings:
    $key_2a65 = { 7d 17 [2] 4f 35 [2] 49 00 [2] 67 00 [2] 58 1c }

  condition:
    any of them
}