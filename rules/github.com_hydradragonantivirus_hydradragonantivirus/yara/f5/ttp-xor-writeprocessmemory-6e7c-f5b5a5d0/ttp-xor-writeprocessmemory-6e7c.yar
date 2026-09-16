rule TTP_XOR_WriteProcessMemory_6e7c {
  strings:
    $key_6e7c = { 39 0e [2] 0b 2c [2] 0d 19 [2] 23 19 [2] 1c 05 }

  condition:
    any of them
}