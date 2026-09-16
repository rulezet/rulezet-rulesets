rule TTP_XOR_WriteProcessMemory_234f {
  strings:
    $key_234f = { 74 3d [2] 46 1f [2] 40 2a [2] 6e 2a [2] 51 36 }

  condition:
    any of them
}