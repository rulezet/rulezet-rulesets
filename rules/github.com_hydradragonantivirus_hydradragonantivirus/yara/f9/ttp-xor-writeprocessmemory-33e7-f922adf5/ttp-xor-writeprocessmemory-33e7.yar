rule TTP_XOR_WriteProcessMemory_33e7 {
  strings:
    $key_33e7 = { 64 95 [2] 56 b7 [2] 50 82 [2] 7e 82 [2] 41 9e }

  condition:
    any of them
}