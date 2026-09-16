rule TTP_XOR_WriteProcessMemory_444f {
  strings:
    $key_444f = { 13 3d [2] 21 1f [2] 27 2a [2] 09 2a [2] 36 36 }

  condition:
    any of them
}