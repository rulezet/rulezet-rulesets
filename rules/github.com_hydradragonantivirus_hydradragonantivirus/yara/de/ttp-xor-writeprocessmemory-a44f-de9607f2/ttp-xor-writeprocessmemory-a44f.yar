rule TTP_XOR_WriteProcessMemory_a44f {
  strings:
    $key_a44f = { f3 3d [2] c1 1f [2] c7 2a [2] e9 2a [2] d6 36 }

  condition:
    any of them
}