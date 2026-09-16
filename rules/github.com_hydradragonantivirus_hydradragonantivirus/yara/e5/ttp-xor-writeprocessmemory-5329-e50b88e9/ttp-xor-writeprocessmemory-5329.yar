rule TTP_XOR_WriteProcessMemory_5329 {
  strings:
    $key_5329 = { 04 5b [2] 36 79 [2] 30 4c [2] 1e 4c [2] 21 50 }

  condition:
    any of them
}