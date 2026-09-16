rule TTP_XOR_WriteProcessMemory_387c {
  strings:
    $key_387c = { 6f 0e [2] 5d 2c [2] 5b 19 [2] 75 19 [2] 4a 05 }

  condition:
    any of them
}