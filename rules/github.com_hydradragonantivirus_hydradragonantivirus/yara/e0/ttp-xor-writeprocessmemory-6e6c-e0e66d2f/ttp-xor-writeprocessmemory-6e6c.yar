rule TTP_XOR_WriteProcessMemory_6e6c {
  strings:
    $key_6e6c = { 39 1e [2] 0b 3c [2] 0d 09 [2] 23 09 [2] 1c 15 }

  condition:
    any of them
}