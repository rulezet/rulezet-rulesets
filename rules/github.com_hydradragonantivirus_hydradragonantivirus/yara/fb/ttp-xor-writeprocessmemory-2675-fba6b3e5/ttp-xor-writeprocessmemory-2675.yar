rule TTP_XOR_WriteProcessMemory_2675 {
  strings:
    $key_2675 = { 71 07 [2] 43 25 [2] 45 10 [2] 6b 10 [2] 54 0c }

  condition:
    any of them
}