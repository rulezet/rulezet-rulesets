rule TTP_XOR_WriteProcessMemory_5645 {
  strings:
    $key_5645 = { 01 37 [2] 33 15 [2] 35 20 [2] 1b 20 [2] 24 3c }

  condition:
    any of them
}