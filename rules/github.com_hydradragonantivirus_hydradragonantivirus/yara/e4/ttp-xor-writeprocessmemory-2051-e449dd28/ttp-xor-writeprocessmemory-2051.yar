rule TTP_XOR_WriteProcessMemory_2051 {
  strings:
    $key_2051 = { 77 23 [2] 45 01 [2] 43 34 [2] 6d 34 [2] 52 28 }

  condition:
    any of them
}