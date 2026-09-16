rule TTP_XOR_WriteProcessMemory_0f3b {
  strings:
    $key_0f3b = { 58 49 [2] 6a 6b [2] 6c 5e [2] 42 5e [2] 7d 42 }

  condition:
    any of them
}