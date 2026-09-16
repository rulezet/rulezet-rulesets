rule TTP_XOR_WriteProcessMemory_0568 {
  strings:
    $key_0568 = { 52 1a [2] 60 38 [2] 66 0d [2] 48 0d [2] 77 11 }

  condition:
    any of them
}