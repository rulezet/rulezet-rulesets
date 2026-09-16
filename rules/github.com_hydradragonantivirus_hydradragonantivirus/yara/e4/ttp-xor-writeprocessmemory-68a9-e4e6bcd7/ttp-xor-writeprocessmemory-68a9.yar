rule TTP_XOR_WriteProcessMemory_68a9 {
  strings:
    $key_68a9 = { 3f db [2] 0d f9 [2] 0b cc [2] 25 cc [2] 1a d0 }

  condition:
    any of them
}