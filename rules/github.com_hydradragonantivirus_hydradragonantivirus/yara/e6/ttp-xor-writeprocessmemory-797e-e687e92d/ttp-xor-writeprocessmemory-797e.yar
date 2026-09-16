rule TTP_XOR_WriteProcessMemory_797e {
  strings:
    $key_797e = { 2e 0c [2] 1c 2e [2] 1a 1b [2] 34 1b [2] 0b 07 }

  condition:
    any of them
}