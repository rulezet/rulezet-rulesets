rule TTP_XOR_WriteProcessMemory_4b1c {
  strings:
    $key_4b1c = { 1c 6e [2] 2e 4c [2] 28 79 [2] 06 79 [2] 39 65 }

  condition:
    any of them
}