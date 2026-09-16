rule TTP_XOR_WriteProcessMemory_b75f {
  strings:
    $key_b75f = { e0 2d [2] d2 0f [2] d4 3a [2] fa 3a [2] c5 26 }

  condition:
    any of them
}