rule TTP_XOR_WriteProcessMemory_4b6e {
  strings:
    $key_4b6e = { 1c 1c [2] 2e 3e [2] 28 0b [2] 06 0b [2] 39 17 }

  condition:
    any of them
}