rule TTP_XOR_WriteProcessMemory_ff6c {
  strings:
    $key_ff6c = { a8 1e [2] 9a 3c [2] 9c 09 [2] b2 09 [2] 8d 15 }

  condition:
    any of them
}