rule TTP_XOR_WriteProcessMemory_4e2c {
  strings:
    $key_4e2c = { 19 5e [2] 2b 7c [2] 2d 49 [2] 03 49 [2] 3c 55 }

  condition:
    any of them
}