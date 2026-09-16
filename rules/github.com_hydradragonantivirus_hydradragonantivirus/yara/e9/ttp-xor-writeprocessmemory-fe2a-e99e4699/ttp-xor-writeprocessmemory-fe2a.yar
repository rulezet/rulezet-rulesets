rule TTP_XOR_WriteProcessMemory_fe2a {
  strings:
    $key_fe2a = { a9 58 [2] 9b 7a [2] 9d 4f [2] b3 4f [2] 8c 53 }

  condition:
    any of them
}