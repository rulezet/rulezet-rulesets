rule TTP_XOR_WriteProcessMemory_6f4f {
  strings:
    $key_6f4f = { 38 3d [2] 0a 1f [2] 0c 2a [2] 22 2a [2] 1d 36 }

  condition:
    any of them
}