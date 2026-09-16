rule TTP_XOR_WriteProcessMemory_0829 {
  strings:
    $key_0829 = { 5f 5b [2] 6d 79 [2] 6b 4c [2] 45 4c [2] 7a 50 }

  condition:
    any of them
}