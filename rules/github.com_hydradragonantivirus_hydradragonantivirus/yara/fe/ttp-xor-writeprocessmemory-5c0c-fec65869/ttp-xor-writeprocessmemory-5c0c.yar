rule TTP_XOR_WriteProcessMemory_5c0c {
  strings:
    $key_5c0c = { 0b 7e [2] 39 5c [2] 3f 69 [2] 11 69 [2] 2e 75 }

  condition:
    any of them
}