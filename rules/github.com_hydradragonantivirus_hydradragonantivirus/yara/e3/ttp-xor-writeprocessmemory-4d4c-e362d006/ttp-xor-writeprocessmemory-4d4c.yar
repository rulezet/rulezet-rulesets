rule TTP_XOR_WriteProcessMemory_4d4c {
  strings:
    $key_4d4c = { 1a 3e [2] 28 1c [2] 2e 29 [2] 00 29 [2] 3f 35 }

  condition:
    any of them
}