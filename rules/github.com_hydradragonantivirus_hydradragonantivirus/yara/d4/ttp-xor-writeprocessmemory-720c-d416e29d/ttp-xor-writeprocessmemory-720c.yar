rule TTP_XOR_WriteProcessMemory_720c {
  strings:
    $key_720c = { 25 7e [2] 17 5c [2] 11 69 [2] 3f 69 [2] 00 75 }

  condition:
    any of them
}