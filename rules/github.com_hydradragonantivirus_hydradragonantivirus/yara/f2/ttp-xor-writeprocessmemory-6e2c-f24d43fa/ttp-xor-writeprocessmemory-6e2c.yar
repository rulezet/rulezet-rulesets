rule TTP_XOR_WriteProcessMemory_6e2c {
  strings:
    $key_6e2c = { 39 5e [2] 0b 7c [2] 0d 49 [2] 23 49 [2] 1c 55 }

  condition:
    any of them
}