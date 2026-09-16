rule TTP_XOR_WriteProcessMemory_1932 {
  strings:
    $key_1932 = { 4e 40 [2] 7c 62 [2] 7a 57 [2] 54 57 [2] 6b 4b }

  condition:
    any of them
}