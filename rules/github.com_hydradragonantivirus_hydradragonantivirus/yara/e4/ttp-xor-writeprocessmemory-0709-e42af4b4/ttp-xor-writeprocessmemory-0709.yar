rule TTP_XOR_WriteProcessMemory_0709 {
  strings:
    $key_0709 = { 50 7b [2] 62 59 [2] 64 6c [2] 4a 6c [2] 75 70 }

  condition:
    any of them
}