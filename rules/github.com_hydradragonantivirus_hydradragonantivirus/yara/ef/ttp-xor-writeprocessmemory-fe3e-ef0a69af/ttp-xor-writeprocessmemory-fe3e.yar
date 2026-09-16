rule TTP_XOR_WriteProcessMemory_fe3e {
  strings:
    $key_fe3e = { a9 4c [2] 9b 6e [2] 9d 5b [2] b3 5b [2] 8c 47 }

  condition:
    any of them
}