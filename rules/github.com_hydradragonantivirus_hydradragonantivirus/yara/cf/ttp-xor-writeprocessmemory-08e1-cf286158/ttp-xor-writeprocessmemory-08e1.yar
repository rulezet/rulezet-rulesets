rule TTP_XOR_WriteProcessMemory_08e1 {
  strings:
    $key_08e1 = { 5f 93 [2] 6d b1 [2] 6b 84 [2] 45 84 [2] 7a 98 }

  condition:
    any of them
}