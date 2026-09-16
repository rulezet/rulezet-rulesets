rule TTP_XOR_WriteProcessMemory_0b0c {
  strings:
    $key_0b0c = { 5c 7e [2] 6e 5c [2] 68 69 [2] 46 69 [2] 79 75 }

  condition:
    any of them
}