rule TTP_XOR_WriteProcessMemory_2635 {
  strings:
    $key_2635 = { 71 47 [2] 43 65 [2] 45 50 [2] 6b 50 [2] 54 4c }

  condition:
    any of them
}