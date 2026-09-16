rule TTP_XOR_WriteProcessMemory_0759 {
  strings:
    $key_0759 = { 50 2b [2] 62 09 [2] 64 3c [2] 4a 3c [2] 75 20 }

  condition:
    any of them
}