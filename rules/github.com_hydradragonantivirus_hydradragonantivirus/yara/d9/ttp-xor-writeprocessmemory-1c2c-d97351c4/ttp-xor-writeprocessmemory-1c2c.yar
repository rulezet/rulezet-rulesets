rule TTP_XOR_WriteProcessMemory_1c2c {
  strings:
    $key_1c2c = { 4b 5e [2] 79 7c [2] 7f 49 [2] 51 49 [2] 6e 55 }

  condition:
    any of them
}