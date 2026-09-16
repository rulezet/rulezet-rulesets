rule TTP_XOR_WriteProcessMemory_fe1c {
  strings:
    $key_fe1c = { a9 6e [2] 9b 4c [2] 9d 79 [2] b3 79 [2] 8c 65 }

  condition:
    any of them
}