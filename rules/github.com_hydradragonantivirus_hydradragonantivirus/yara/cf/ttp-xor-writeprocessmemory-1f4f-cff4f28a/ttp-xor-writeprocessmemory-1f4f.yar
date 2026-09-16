rule TTP_XOR_WriteProcessMemory_1f4f {
  strings:
    $key_1f4f = { 48 3d [2] 7a 1f [2] 7c 2a [2] 52 2a [2] 6d 36 }

  condition:
    any of them
}