rule TTP_XOR_WriteProcessMemory_7e6e {
  strings:
    $key_7e6e = { 29 1c [2] 1b 3e [2] 1d 0b [2] 33 0b [2] 0c 17 }

  condition:
    any of them
}