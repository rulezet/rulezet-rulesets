rule TTP_XOR_WriteProcessMemory_2094 {
  strings:
    $key_2094 = { 77 e6 [2] 45 c4 [2] 43 f1 [2] 6d f1 [2] 52 ed }

  condition:
    any of them
}