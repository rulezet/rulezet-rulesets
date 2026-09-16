rule TTP_XOR_WriteProcessMemory_a64f {
  strings:
    $key_a64f = { f1 3d [2] c3 1f [2] c5 2a [2] eb 2a [2] d4 36 }

  condition:
    any of them
}