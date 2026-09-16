rule TTP_XOR_WriteProcessMemory_b71f {
  strings:
    $key_b71f = { e0 6d [2] d2 4f [2] d4 7a [2] fa 7a [2] c5 66 }

  condition:
    any of them
}