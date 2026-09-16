rule TTP_XOR_WriteProcessMemory_5da2 {
  strings:
    $key_5da2 = { 0a d0 [2] 38 f2 [2] 3e c7 [2] 10 c7 [2] 2f db }

  condition:
    any of them
}