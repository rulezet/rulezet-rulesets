rule TTP_XOR_WriteProcessMemory_163b {
  strings:
    $key_163b = { 41 49 [2] 73 6b [2] 75 5e [2] 5b 5e [2] 64 42 }

  condition:
    any of them
}