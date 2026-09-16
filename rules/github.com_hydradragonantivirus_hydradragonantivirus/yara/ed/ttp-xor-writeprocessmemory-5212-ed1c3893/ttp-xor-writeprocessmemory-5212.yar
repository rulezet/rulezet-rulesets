rule TTP_XOR_WriteProcessMemory_5212 {
  strings:
    $key_5212 = { 05 60 [2] 37 42 [2] 31 77 [2] 1f 77 [2] 20 6b }

  condition:
    any of them
}