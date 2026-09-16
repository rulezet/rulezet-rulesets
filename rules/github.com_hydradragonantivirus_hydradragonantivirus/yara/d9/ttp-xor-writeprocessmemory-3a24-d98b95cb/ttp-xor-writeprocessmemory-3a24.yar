rule TTP_XOR_WriteProcessMemory_3a24 {
  strings:
    $key_3a24 = { 6d 56 [2] 5f 74 [2] 59 41 [2] 77 41 [2] 48 5d }

  condition:
    any of them
}