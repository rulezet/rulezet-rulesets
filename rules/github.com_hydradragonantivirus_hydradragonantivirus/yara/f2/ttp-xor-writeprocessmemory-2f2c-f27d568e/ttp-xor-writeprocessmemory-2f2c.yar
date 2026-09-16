rule TTP_XOR_WriteProcessMemory_2f2c {
  strings:
    $key_2f2c = { 78 5e [2] 4a 7c [2] 4c 49 [2] 62 49 [2] 5d 55 }

  condition:
    any of them
}