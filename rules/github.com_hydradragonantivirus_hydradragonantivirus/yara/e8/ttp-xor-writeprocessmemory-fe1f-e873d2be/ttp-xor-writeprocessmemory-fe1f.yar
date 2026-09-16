rule TTP_XOR_WriteProcessMemory_fe1f {
  strings:
    $key_fe1f = { a9 6d [2] 9b 4f [2] 9d 7a [2] b3 7a [2] 8c 66 }

  condition:
    any of them
}