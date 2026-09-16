rule TTP_XOR_WriteProcessMemory_35f8 {
  strings:
    $key_35f8 = { 62 8a [2] 50 a8 [2] 56 9d [2] 78 9d [2] 47 81 }

  condition:
    any of them
}