rule TTP_XOR_WriteProcessMemory_2637 {
  strings:
    $key_2637 = { 71 45 [2] 43 67 [2] 45 52 [2] 6b 52 [2] 54 4e }

  condition:
    any of them
}