rule TTP_XOR_WriteProcessMemory_3b6e {
  strings:
    $key_3b6e = { 6c 1c [2] 5e 3e [2] 58 0b [2] 76 0b [2] 49 17 }

  condition:
    any of them
}