rule TTP_XOR_WriteProcessMemory_ff1c {
  strings:
    $key_ff1c = { a8 6e [2] 9a 4c [2] 9c 79 [2] b2 79 [2] 8d 65 }

  condition:
    any of them
}