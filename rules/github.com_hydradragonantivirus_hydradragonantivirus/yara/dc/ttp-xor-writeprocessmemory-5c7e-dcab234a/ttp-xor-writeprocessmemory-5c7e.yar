rule TTP_XOR_WriteProcessMemory_5c7e {
  strings:
    $key_5c7e = { 0b 0c [2] 39 2e [2] 3f 1b [2] 11 1b [2] 2e 07 }

  condition:
    any of them
}