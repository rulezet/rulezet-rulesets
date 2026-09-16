rule TTP_XOR_WriteProcessMemory_0b4f {
  strings:
    $key_0b4f = { 5c 3d [2] 6e 1f [2] 68 2a [2] 46 2a [2] 79 36 }

  condition:
    any of them
}