rule TTP_XOR_WriteProcessMemory_ff7d {
  strings:
    $key_ff7d = { a8 0f [2] 9a 2d [2] 9c 18 [2] b2 18 [2] 8d 04 }

  condition:
    any of them
}