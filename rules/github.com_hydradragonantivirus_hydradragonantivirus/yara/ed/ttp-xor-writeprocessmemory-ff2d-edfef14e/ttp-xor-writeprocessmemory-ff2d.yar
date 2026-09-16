rule TTP_XOR_WriteProcessMemory_ff2d {
  strings:
    $key_ff2d = { a8 5f [2] 9a 7d [2] 9c 48 [2] b2 48 [2] 8d 54 }

  condition:
    any of them
}