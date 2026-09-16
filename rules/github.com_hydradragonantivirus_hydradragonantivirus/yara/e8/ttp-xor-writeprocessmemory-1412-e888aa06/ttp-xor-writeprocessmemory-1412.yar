rule TTP_XOR_WriteProcessMemory_1412 {
  strings:
    $key_1412 = { 43 60 [2] 71 42 [2] 77 77 [2] 59 77 [2] 66 6b }

  condition:
    any of them
}