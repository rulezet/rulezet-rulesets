rule TTP_XOR_WriteProcessMemory_5030 {
  strings:
    $key_5030 = { 07 42 [2] 35 60 [2] 33 55 [2] 1d 55 [2] 22 49 }

  condition:
    any of them
}