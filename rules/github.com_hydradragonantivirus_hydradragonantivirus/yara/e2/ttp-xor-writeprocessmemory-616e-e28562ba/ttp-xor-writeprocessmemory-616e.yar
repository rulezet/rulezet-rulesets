rule TTP_XOR_WriteProcessMemory_616e {
  strings:
    $key_616e = { 36 1c [2] 04 3e [2] 02 0b [2] 2c 0b [2] 13 17 }

  condition:
    any of them
}