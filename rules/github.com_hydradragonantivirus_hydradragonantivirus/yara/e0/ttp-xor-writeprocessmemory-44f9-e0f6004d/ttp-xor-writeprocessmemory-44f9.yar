rule TTP_XOR_WriteProcessMemory_44f9 {
  strings:
    $key_44f9 = { 13 8b [2] 21 a9 [2] 27 9c [2] 09 9c [2] 36 80 }

  condition:
    any of them
}