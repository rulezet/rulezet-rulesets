rule TTP_XOR_WriteProcessMemory_434f {
  strings:
    $key_434f = { 14 3d [2] 26 1f [2] 20 2a [2] 0e 2a [2] 31 36 }

  condition:
    any of them
}