rule TTP_XOR_WriteProcessMemory_ff6a {
  strings:
    $key_ff6a = { a8 18 [2] 9a 3a [2] 9c 0f [2] b2 0f [2] 8d 13 }

  condition:
    any of them
}