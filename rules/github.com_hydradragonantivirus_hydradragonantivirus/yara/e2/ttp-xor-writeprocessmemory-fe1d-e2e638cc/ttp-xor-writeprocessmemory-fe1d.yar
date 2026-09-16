rule TTP_XOR_WriteProcessMemory_fe1d {
  strings:
    $key_fe1d = { a9 6f [2] 9b 4d [2] 9d 78 [2] b3 78 [2] 8c 64 }

  condition:
    any of them
}