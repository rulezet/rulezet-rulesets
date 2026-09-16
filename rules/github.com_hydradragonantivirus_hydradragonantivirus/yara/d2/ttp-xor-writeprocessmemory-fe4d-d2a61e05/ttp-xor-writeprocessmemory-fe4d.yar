rule TTP_XOR_WriteProcessMemory_fe4d {
  strings:
    $key_fe4d = { a9 3f [2] 9b 1d [2] 9d 28 [2] b3 28 [2] 8c 34 }

  condition:
    any of them
}