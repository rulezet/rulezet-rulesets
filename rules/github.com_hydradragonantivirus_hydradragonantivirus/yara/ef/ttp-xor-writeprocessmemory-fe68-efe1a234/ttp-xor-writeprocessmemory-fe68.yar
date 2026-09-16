rule TTP_XOR_WriteProcessMemory_fe68 {
  strings:
    $key_fe68 = { a9 1a [2] 9b 38 [2] 9d 0d [2] b3 0d [2] 8c 11 }

  condition:
    any of them
}