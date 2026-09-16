rule TTP_XOR_WriteProcessMemory_2720 {
  strings:
    $key_2720 = { 70 52 [2] 42 70 [2] 44 45 [2] 6a 45 [2] 55 59 }

  condition:
    any of them
}