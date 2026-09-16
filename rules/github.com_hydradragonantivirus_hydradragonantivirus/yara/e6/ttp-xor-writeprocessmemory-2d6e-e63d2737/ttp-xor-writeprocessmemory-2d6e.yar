rule TTP_XOR_WriteProcessMemory_2d6e {
  strings:
    $key_2d6e = { 7a 1c [2] 48 3e [2] 4e 0b [2] 60 0b [2] 5f 17 }

  condition:
    any of them
}