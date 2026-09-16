rule TTP_XOR_WriteProcessMemory_4a2c {
  strings:
    $key_4a2c = { 1d 5e [2] 2f 7c [2] 29 49 [2] 07 49 [2] 38 55 }

  condition:
    any of them
}