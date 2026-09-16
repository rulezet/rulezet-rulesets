rule TTP_XOR_WriteProcessMemory_fefb {
  strings:
    $key_fefb = { a9 89 [2] 9b ab [2] 9d 9e [2] b3 9e [2] 8c 82 }

  condition:
    any of them
}