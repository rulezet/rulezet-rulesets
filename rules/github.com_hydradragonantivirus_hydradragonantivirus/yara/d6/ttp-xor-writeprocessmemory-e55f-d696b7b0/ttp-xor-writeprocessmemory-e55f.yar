rule TTP_XOR_WriteProcessMemory_e55f {
  strings:
    $key_e55f = { b2 2d [2] 80 0f [2] 86 3a [2] a8 3a [2] 97 26 }

  condition:
    any of them
}