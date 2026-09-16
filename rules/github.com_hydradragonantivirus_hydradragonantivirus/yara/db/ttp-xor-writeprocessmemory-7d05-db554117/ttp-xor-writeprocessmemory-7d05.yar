rule TTP_XOR_WriteProcessMemory_7d05 {
  strings:
    $key_7d05 = { 2a 77 [2] 18 55 [2] 1e 60 [2] 30 60 [2] 0f 7c }

  condition:
    any of them
}