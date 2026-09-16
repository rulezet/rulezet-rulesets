rule TTP_XOR_WriteProcessMemory_4559 {
  strings:
    $key_4559 = { 12 2b [2] 20 09 [2] 26 3c [2] 08 3c [2] 37 20 }

  condition:
    any of them
}