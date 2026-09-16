rule TTP_XOR_WriteProcessMemory_7348 {
  strings:
    $key_7348 = { 24 3a [2] 16 18 [2] 10 2d [2] 3e 2d [2] 01 31 }

  condition:
    any of them
}