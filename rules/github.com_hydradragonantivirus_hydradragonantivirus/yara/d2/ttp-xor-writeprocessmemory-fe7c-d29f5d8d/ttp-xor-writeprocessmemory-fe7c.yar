rule TTP_XOR_WriteProcessMemory_fe7c {
  strings:
    $key_fe7c = { a9 0e [2] 9b 2c [2] 9d 19 [2] b3 19 [2] 8c 05 }

  condition:
    any of them
}