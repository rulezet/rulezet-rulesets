rule TTP_XOR_WriteProcessMemory_763d {
  strings:
    $key_763d = { 21 4f [2] 13 6d [2] 15 58 [2] 3b 58 [2] 04 44 }

  condition:
    any of them
}