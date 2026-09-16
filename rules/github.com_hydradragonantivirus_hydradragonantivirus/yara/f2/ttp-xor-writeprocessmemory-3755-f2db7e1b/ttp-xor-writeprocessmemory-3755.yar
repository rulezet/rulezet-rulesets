rule TTP_XOR_WriteProcessMemory_3755 {
  strings:
    $key_3755 = { 60 27 [2] 52 05 [2] 54 30 [2] 7a 30 [2] 45 2c }

  condition:
    any of them
}