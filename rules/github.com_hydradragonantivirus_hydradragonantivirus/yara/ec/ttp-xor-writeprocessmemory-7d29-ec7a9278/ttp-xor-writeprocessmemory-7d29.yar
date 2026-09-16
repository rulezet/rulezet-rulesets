rule TTP_XOR_WriteProcessMemory_7d29 {
  strings:
    $key_7d29 = { 2a 5b [2] 18 79 [2] 1e 4c [2] 30 4c [2] 0f 50 }

  condition:
    any of them
}