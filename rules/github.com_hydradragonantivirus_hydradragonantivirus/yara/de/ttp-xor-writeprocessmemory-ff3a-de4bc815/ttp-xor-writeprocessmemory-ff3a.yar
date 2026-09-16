rule TTP_XOR_WriteProcessMemory_ff3a {
  strings:
    $key_ff3a = { a8 48 [2] 9a 6a [2] 9c 5f [2] b2 5f [2] 8d 43 }

  condition:
    any of them
}