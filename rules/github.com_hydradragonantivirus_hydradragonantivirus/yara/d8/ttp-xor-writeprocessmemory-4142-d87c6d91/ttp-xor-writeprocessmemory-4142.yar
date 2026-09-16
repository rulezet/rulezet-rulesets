rule TTP_XOR_WriteProcessMemory_4142 {
  strings:
    $key_4142 = { 16 30 [2] 24 12 [2] 22 27 [2] 0c 27 [2] 33 3b }

  condition:
    any of them
}