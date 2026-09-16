rule TTP_XOR_WriteProcessMemory_474d {
  strings:
    $key_474d = { 10 3f [2] 22 1d [2] 24 28 [2] 0a 28 [2] 35 34 }

  condition:
    any of them
}