rule TTP_XOR_WriteProcessMemory_3a3d {
  strings:
    $key_3a3d = { 6d 4f [2] 5f 6d [2] 59 58 [2] 77 58 [2] 48 44 }

  condition:
    any of them
}