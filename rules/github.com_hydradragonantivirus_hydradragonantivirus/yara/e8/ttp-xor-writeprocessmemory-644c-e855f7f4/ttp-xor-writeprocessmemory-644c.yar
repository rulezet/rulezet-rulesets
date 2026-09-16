rule TTP_XOR_WriteProcessMemory_644c {
  strings:
    $key_644c = { 33 3e [2] 01 1c [2] 07 29 [2] 29 29 [2] 16 35 }

  condition:
    any of them
}