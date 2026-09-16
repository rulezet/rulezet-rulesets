rule TTP_XOR_WriteProcessMemory_d8f9 {
  strings:
    $key_d8f9 = { 8f 8b [2] bd a9 [2] bb 9c [2] 95 9c [2] aa 80 }

  condition:
    any of them
}