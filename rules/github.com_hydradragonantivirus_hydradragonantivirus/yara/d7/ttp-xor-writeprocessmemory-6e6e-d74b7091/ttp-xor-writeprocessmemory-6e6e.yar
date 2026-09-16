rule TTP_XOR_WriteProcessMemory_6e6e {
  strings:
    $key_6e6e = { 39 1c [2] 0b 3e [2] 0d 0b [2] 23 0b [2] 1c 17 }

  condition:
    any of them
}