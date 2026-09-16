rule TTP_XOR_WriteProcessMemory_6f2c {
  strings:
    $key_6f2c = { 38 5e [2] 0a 7c [2] 0c 49 [2] 22 49 [2] 1d 55 }

  condition:
    any of them
}