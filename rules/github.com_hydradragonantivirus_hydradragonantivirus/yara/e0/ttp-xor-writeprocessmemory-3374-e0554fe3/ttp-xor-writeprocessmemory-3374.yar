rule TTP_XOR_WriteProcessMemory_3374 {
  strings:
    $key_3374 = { 64 06 [2] 56 24 [2] 50 11 [2] 7e 11 [2] 41 0d }

  condition:
    any of them
}