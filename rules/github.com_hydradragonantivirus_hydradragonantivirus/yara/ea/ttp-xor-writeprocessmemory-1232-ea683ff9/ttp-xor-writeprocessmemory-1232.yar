rule TTP_XOR_WriteProcessMemory_1232 {
  strings:
    $key_1232 = { 45 40 [2] 77 62 [2] 71 57 [2] 5f 57 [2] 60 4b }

  condition:
    any of them
}