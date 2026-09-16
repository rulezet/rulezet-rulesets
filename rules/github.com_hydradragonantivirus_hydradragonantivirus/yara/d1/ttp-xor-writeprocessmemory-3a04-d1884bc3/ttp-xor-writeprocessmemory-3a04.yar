rule TTP_XOR_WriteProcessMemory_3a04 {
  strings:
    $key_3a04 = { 6d 76 [2] 5f 54 [2] 59 61 [2] 77 61 [2] 48 7d }

  condition:
    any of them
}