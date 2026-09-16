rule TTP_XOR_WriteProcessMemory_3a2d {
  strings:
    $key_3a2d = { 6d 5f [2] 5f 7d [2] 59 48 [2] 77 48 [2] 48 54 }

  condition:
    any of them
}