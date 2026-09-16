rule TTP_XOR_WriteProcessMemory_ff4e {
  strings:
    $key_ff4e = { a8 3c [2] 9a 1e [2] 9c 2b [2] b2 2b [2] 8d 37 }

  condition:
    any of them
}