rule TTP_XOR_WriteProcessMemory_1c5c {
  strings:
    $key_1c5c = { 4b 2e [2] 79 0c [2] 7f 39 [2] 51 39 [2] 6e 25 }

  condition:
    any of them
}