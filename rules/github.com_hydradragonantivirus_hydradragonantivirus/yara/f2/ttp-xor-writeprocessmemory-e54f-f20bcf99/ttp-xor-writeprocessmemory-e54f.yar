rule TTP_XOR_WriteProcessMemory_e54f {
  strings:
    $key_e54f = { b2 3d [2] 80 1f [2] 86 2a [2] a8 2a [2] 97 36 }

  condition:
    any of them
}