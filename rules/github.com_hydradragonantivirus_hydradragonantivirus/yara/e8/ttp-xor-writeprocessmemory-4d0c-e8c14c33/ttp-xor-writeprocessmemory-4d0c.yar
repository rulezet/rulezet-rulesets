rule TTP_XOR_WriteProcessMemory_4d0c {
  strings:
    $key_4d0c = { 1a 7e [2] 28 5c [2] 2e 69 [2] 00 69 [2] 3f 75 }

  condition:
    any of them
}