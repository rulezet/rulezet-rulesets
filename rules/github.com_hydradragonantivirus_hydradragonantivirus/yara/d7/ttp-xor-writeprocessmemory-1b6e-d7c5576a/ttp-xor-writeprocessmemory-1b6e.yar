rule TTP_XOR_WriteProcessMemory_1b6e {
  strings:
    $key_1b6e = { 4c 1c [2] 7e 3e [2] 78 0b [2] 56 0b [2] 69 17 }

  condition:
    any of them
}