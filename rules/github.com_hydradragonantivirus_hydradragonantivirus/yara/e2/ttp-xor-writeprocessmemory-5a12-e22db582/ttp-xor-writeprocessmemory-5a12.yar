rule TTP_XOR_WriteProcessMemory_5a12 {
  strings:
    $key_5a12 = { 0d 60 [2] 3f 42 [2] 39 77 [2] 17 77 [2] 28 6b }

  condition:
    any of them
}