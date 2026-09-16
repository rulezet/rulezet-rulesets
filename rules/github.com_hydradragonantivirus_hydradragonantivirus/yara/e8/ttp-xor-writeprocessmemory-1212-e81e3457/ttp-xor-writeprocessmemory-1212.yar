rule TTP_XOR_WriteProcessMemory_1212 {
  strings:
    $key_1212 = { 45 60 [2] 77 42 [2] 71 77 [2] 5f 77 [2] 60 6b }

  condition:
    any of them
}