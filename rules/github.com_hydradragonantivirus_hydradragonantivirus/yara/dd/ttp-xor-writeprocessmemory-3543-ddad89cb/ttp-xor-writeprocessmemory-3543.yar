rule TTP_XOR_WriteProcessMemory_3543 {
  strings:
    $key_3543 = { 62 31 [2] 50 13 [2] 56 26 [2] 78 26 [2] 47 3a }

  condition:
    any of them
}