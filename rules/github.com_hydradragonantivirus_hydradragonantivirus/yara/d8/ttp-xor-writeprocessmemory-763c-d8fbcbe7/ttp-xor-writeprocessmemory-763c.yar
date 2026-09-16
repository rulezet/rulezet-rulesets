rule TTP_XOR_WriteProcessMemory_763c {
  strings:
    $key_763c = { 21 4e [2] 13 6c [2] 15 59 [2] 3b 59 [2] 04 45 }

  condition:
    any of them
}