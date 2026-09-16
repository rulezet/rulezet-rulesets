rule TTP_XOR_WriteProcessMemory_114f {
  strings:
    $key_114f = { 46 3d [2] 74 1f [2] 72 2a [2] 5c 2a [2] 63 36 }

  condition:
    any of them
}