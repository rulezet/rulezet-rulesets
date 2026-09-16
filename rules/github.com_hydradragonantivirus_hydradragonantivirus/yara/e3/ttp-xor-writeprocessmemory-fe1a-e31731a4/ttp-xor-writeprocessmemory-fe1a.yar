rule TTP_XOR_WriteProcessMemory_fe1a {
  strings:
    $key_fe1a = { a9 68 [2] 9b 4a [2] 9d 7f [2] b3 7f [2] 8c 63 }

  condition:
    any of them
}