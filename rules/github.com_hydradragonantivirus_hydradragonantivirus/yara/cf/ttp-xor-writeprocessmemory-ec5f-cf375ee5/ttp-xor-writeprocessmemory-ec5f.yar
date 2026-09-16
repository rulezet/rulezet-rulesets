rule TTP_XOR_WriteProcessMemory_ec5f {
  strings:
    $key_ec5f = { bb 2d [2] 89 0f [2] 8f 3a [2] a1 3a [2] 9e 26 }

  condition:
    any of them
}