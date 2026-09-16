rule TTP_XOR_WriteProcessMemory_2093 {
  strings:
    $key_2093 = { 77 e1 [2] 45 c3 [2] 43 f6 [2] 6d f6 [2] 52 ea }

  condition:
    any of them
}