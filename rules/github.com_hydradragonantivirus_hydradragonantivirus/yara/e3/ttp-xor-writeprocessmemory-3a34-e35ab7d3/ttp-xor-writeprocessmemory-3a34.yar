rule TTP_XOR_WriteProcessMemory_3a34 {
  strings:
    $key_3a34 = { 6d 46 [2] 5f 64 [2] 59 51 [2] 77 51 [2] 48 4d }

  condition:
    any of them
}