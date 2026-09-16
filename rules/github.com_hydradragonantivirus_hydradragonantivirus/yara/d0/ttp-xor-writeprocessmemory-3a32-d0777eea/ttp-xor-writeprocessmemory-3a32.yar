rule TTP_XOR_WriteProcessMemory_3a32 {
  strings:
    $key_3a32 = { 6d 40 [2] 5f 62 [2] 59 57 [2] 77 57 [2] 48 4b }

  condition:
    any of them
}