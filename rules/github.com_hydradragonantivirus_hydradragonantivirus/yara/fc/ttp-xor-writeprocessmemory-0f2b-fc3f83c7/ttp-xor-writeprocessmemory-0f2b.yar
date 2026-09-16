rule TTP_XOR_WriteProcessMemory_0f2b {
  strings:
    $key_0f2b = { 58 59 [2] 6a 7b [2] 6c 4e [2] 42 4e [2] 7d 52 }

  condition:
    any of them
}