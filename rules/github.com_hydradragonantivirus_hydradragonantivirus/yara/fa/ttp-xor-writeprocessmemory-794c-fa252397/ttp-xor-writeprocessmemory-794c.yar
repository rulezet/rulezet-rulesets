rule TTP_XOR_WriteProcessMemory_794c {
  strings:
    $key_794c = { 2e 3e [2] 1c 1c [2] 1a 29 [2] 34 29 [2] 0b 35 }

  condition:
    any of them
}