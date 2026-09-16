rule TTP_XOR_WriteProcessMemory_1c6e {
  strings:
    $key_1c6e = { 4b 1c [2] 79 3e [2] 7f 0b [2] 51 0b [2] 6e 17 }

  condition:
    any of them
}