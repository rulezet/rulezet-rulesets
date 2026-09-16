rule TTP_XOR_WriteProcessMemory_3a61 {
  strings:
    $key_3a61 = { 6d 13 [2] 5f 31 [2] 59 04 [2] 77 04 [2] 48 18 }

  condition:
    any of them
}