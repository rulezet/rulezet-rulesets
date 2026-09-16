rule TTP_XOR_WriteProcessMemory_ff7b {
  strings:
    $key_ff7b = { a8 09 [2] 9a 2b [2] 9c 1e [2] b2 1e [2] 8d 02 }

  condition:
    any of them
}