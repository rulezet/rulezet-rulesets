rule TTP_XOR_WriteProcessMemory_3a5d {
  strings:
    $key_3a5d = { 6d 2f [2] 5f 0d [2] 59 38 [2] 77 38 [2] 48 24 }

  condition:
    any of them
}