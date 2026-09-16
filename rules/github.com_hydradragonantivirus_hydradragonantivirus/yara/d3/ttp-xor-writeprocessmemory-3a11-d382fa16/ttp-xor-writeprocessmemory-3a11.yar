rule TTP_XOR_WriteProcessMemory_3a11 {
  strings:
    $key_3a11 = { 6d 63 [2] 5f 41 [2] 59 74 [2] 77 74 [2] 48 68 }

  condition:
    any of them
}