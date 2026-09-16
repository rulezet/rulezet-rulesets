rule TTP_XOR_WriteProcessMemory_5f19 {
  strings:
    $key_5f19 = { 08 6b [2] 3a 49 [2] 3c 7c [2] 12 7c [2] 2d 60 }

  condition:
    any of them
}