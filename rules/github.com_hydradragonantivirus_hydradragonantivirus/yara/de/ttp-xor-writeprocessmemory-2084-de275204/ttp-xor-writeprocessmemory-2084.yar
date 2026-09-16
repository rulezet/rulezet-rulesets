rule TTP_XOR_WriteProcessMemory_2084 {
  strings:
    $key_2084 = { 77 f6 [2] 45 d4 [2] 43 e1 [2] 6d e1 [2] 52 fd }

  condition:
    any of them
}