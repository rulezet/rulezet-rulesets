rule TTP_XOR_WriteProcessMemory_3b42 {
  strings:
    $key_3b42 = { 6c 30 [2] 5e 12 [2] 58 27 [2] 76 27 [2] 49 3b }

  condition:
    any of them
}