rule TTP_XOR_WriteProcessMemory_1248 {
  strings:
    $key_1248 = { 45 3a [2] 77 18 [2] 71 2d [2] 5f 2d [2] 60 31 }

  condition:
    any of them
}