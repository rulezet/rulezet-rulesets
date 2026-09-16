rule TTP_XOR_WriteProcessMemory_4215 {
  strings:
    $key_4215 = { 15 67 [2] 27 45 [2] 21 70 [2] 0f 70 [2] 30 6c }

  condition:
    any of them
}