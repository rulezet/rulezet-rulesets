rule TTP_XOR_WriteProcessMemory_5a2c {
  strings:
    $key_5a2c = { 0d 5e [2] 3f 7c [2] 39 49 [2] 17 49 [2] 28 55 }

  condition:
    any of them
}