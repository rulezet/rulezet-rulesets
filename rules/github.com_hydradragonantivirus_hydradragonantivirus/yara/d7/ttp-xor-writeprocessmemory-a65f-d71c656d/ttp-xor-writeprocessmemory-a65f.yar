rule TTP_XOR_WriteProcessMemory_a65f {
  strings:
    $key_a65f = { f1 2d [2] c3 0f [2] c5 3a [2] eb 3a [2] d4 26 }

  condition:
    any of them
}