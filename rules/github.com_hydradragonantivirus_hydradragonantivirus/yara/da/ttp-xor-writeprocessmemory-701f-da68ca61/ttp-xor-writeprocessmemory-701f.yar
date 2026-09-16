rule TTP_XOR_WriteProcessMemory_701f {
  strings:
    $key_701f = { 27 6d [2] 15 4f [2] 13 7a [2] 3d 7a [2] 02 66 }

  condition:
    any of them
}