rule TTP_XOR_WriteProcessMemory_0929 {
  strings:
    $key_0929 = { 5e 5b [2] 6c 79 [2] 6a 4c [2] 44 4c [2] 7b 50 }

  condition:
    any of them
}