rule TTP_XOR_WriteProcessMemory_014f {
  strings:
    $key_014f = { 56 3d [2] 64 1f [2] 62 2a [2] 4c 2a [2] 73 36 }

  condition:
    any of them
}