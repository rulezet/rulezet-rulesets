rule TTP_XOR_WriteProcessMemory_78f9 {
  strings:
    $key_78f9 = { 2f 8b [2] 1d a9 [2] 1b 9c [2] 35 9c [2] 0a 80 }

  condition:
    any of them
}