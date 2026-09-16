rule TTP_XOR_WriteProcessMemory_2d4f {
  strings:
    $key_2d4f = { 7a 3d [2] 48 1f [2] 4e 2a [2] 60 2a [2] 5f 36 }

  condition:
    any of them
}