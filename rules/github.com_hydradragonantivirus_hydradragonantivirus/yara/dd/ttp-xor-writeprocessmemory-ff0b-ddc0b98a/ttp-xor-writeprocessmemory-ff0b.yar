rule TTP_XOR_WriteProcessMemory_ff0b {
  strings:
    $key_ff0b = { a8 79 [2] 9a 5b [2] 9c 6e [2] b2 6e [2] 8d 72 }

  condition:
    any of them
}