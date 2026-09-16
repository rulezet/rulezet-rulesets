rule TTP_XOR_WriteProcessMemory_3a14 {
  strings:
    $key_3a14 = { 6d 66 [2] 5f 44 [2] 59 71 [2] 77 71 [2] 48 6d }

  condition:
    any of them
}