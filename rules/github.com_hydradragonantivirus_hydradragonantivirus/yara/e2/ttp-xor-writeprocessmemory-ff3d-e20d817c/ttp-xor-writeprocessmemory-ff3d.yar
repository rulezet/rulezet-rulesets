rule TTP_XOR_WriteProcessMemory_ff3d {
  strings:
    $key_ff3d = { a8 4f [2] 9a 6d [2] 9c 58 [2] b2 58 [2] 8d 44 }

  condition:
    any of them
}