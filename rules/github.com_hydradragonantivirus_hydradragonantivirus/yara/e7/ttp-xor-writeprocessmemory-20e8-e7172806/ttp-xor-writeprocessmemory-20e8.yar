rule TTP_XOR_WriteProcessMemory_20e8 {
  strings:
    $key_20e8 = { 77 9a [2] 45 b8 [2] 43 8d [2] 6d 8d [2] 52 91 }

  condition:
    any of them
}