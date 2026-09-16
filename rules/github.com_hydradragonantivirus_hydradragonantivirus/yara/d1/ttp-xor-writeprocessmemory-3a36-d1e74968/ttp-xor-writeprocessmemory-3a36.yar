rule TTP_XOR_WriteProcessMemory_3a36 {
  strings:
    $key_3a36 = { 6d 44 [2] 5f 66 [2] 59 53 [2] 77 53 [2] 48 4f }

  condition:
    any of them
}