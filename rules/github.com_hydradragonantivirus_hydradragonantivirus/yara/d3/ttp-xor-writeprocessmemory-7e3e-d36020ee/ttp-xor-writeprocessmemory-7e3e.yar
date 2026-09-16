rule TTP_XOR_WriteProcessMemory_7e3e {
  strings:
    $key_7e3e = { 29 4c [2] 1b 6e [2] 1d 5b [2] 33 5b [2] 0c 47 }

  condition:
    any of them
}