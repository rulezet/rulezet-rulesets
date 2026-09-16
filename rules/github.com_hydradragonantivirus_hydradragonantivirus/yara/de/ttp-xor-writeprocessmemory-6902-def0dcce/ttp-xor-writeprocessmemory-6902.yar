rule TTP_XOR_WriteProcessMemory_6902 {
  strings:
    $key_6902 = { 3e 70 [2] 0c 52 [2] 0a 67 [2] 24 67 [2] 1b 7b }

  condition:
    any of them
}