rule TTP_XOR_WriteProcessMemory_5f59 {
  strings:
    $key_5f59 = { 08 2b [2] 3a 09 [2] 3c 3c [2] 12 3c [2] 2d 20 }

  condition:
    any of them
}