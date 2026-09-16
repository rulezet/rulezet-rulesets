rule TTP_XOR_WriteProcessMemory_210b {
  strings:
    $key_210b = { 76 79 [2] 44 5b [2] 42 6e [2] 6c 6e [2] 53 72 }

  condition:
    any of them
}