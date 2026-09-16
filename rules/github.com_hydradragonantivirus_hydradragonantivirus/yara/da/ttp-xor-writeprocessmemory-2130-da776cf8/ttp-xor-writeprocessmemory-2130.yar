rule TTP_XOR_WriteProcessMemory_2130 {
  strings:
    $key_2130 = { 76 42 [2] 44 60 [2] 42 55 [2] 6c 55 [2] 53 49 }

  condition:
    any of them
}