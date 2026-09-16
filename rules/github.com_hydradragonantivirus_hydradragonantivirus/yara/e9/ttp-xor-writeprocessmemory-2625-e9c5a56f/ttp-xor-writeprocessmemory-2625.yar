rule TTP_XOR_WriteProcessMemory_2625 {
  strings:
    $key_2625 = { 71 57 [2] 43 75 [2] 45 40 [2] 6b 40 [2] 54 5c }

  condition:
    any of them
}