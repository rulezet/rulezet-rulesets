rule TTP_XOR_WriteProcessMemory_4d6c {
  strings:
    $key_4d6c = { 1a 1e [2] 28 3c [2] 2e 09 [2] 00 09 [2] 3f 15 }

  condition:
    any of them
}