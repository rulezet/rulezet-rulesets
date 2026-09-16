rule TTP_XOR_WriteProcessMemory_da4f {
  strings:
    $key_da4f = { 8d 3d [2] bf 1f [2] b9 2a [2] 97 2a [2] a8 36 }

  condition:
    any of them
}