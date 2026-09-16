rule TTP_XOR_WriteProcessMemory_ff58 {
  strings:
    $key_ff58 = { a8 2a [2] 9a 08 [2] 9c 3d [2] b2 3d [2] 8d 21 }

  condition:
    any of them
}