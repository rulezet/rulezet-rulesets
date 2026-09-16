rule TTP_XOR_WriteProcessMemory_2a45 {
  strings:
    $key_2a45 = { 7d 37 [2] 4f 15 [2] 49 20 [2] 67 20 [2] 58 3c }

  condition:
    any of them
}