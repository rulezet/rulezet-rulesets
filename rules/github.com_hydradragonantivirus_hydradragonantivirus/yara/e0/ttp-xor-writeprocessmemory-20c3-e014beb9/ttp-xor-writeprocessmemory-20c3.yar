rule TTP_XOR_WriteProcessMemory_20c3 {
  strings:
    $key_20c3 = { 77 b1 [2] 45 93 [2] 43 a6 [2] 6d a6 [2] 52 ba }

  condition:
    any of them
}