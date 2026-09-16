rule TTP_XOR_WriteProcessMemory_2525 {
  strings:
    $key_2525 = { 72 57 [2] 40 75 [2] 46 40 [2] 68 40 [2] 57 5c }

  condition:
    any of them
}