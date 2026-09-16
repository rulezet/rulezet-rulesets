rule TTP_XOR_WriteProcessMemory_c9e9 {
  strings:
    $key_c9e9 = { 9e 9b [2] ac b9 [2] aa 8c [2] 84 8c [2] bb 90 }

  condition:
    any of them
}