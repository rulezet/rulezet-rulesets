rule TTP_XOR_WriteProcessMemory_2008 {
  strings:
    $key_2008 = { 77 7a [2] 45 58 [2] 43 6d [2] 6d 6d [2] 52 71 }

  condition:
    any of them
}