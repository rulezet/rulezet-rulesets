rule TTP_XOR_WriteProcessMemory_6e5c {
  strings:
    $key_6e5c = { 39 2e [2] 0b 0c [2] 0d 39 [2] 23 39 [2] 1c 25 }

  condition:
    any of them
}