rule TTP_XOR_WriteProcessMemory_ff0f {
  strings:
    $key_ff0f = { a8 7d [2] 9a 5f [2] 9c 6a [2] b2 6a [2] 8d 76 }

  condition:
    any of them
}