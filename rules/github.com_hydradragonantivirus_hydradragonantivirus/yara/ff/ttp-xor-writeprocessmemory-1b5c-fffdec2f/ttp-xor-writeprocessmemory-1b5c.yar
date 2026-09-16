rule TTP_XOR_WriteProcessMemory_1b5c {
  strings:
    $key_1b5c = { 4c 2e [2] 7e 0c [2] 78 39 [2] 56 39 [2] 69 25 }

  condition:
    any of them
}