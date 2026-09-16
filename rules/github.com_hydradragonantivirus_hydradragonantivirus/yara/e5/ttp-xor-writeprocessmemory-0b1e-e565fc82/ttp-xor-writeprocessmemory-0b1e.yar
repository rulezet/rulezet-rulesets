rule TTP_XOR_WriteProcessMemory_0b1e {
  strings:
    $key_0b1e = { 5c 6c [2] 6e 4e [2] 68 7b [2] 46 7b [2] 79 67 }

  condition:
    any of them
}