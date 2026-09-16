rule TTP_XOR_WriteProcessMemory_2725 {
  strings:
    $key_2725 = { 70 57 [2] 42 75 [2] 44 40 [2] 6a 40 [2] 55 5c }

  condition:
    any of them
}