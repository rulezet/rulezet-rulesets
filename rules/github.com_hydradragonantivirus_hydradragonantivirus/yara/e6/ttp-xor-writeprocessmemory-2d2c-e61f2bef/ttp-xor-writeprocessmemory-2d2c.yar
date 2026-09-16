rule TTP_XOR_WriteProcessMemory_2d2c {
  strings:
    $key_2d2c = { 7a 5e [2] 48 7c [2] 4e 49 [2] 60 49 [2] 5f 55 }

  condition:
    any of them
}