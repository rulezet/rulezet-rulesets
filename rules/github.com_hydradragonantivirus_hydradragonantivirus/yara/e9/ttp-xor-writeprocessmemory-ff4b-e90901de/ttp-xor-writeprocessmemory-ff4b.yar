rule TTP_XOR_WriteProcessMemory_ff4b {
  strings:
    $key_ff4b = { a8 39 [2] 9a 1b [2] 9c 2e [2] b2 2e [2] 8d 32 }

  condition:
    any of them
}