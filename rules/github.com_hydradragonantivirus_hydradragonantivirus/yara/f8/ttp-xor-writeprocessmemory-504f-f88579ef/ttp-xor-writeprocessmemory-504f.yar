rule TTP_XOR_WriteProcessMemory_504f {
  strings:
    $key_504f = { 07 3d [2] 35 1f [2] 33 2a [2] 1d 2a [2] 22 36 }

  condition:
    any of them
}