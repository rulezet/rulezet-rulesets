rule TTP_XOR_WriteProcessMemory_e05f {
  strings:
    $key_e05f = { b7 2d [2] 85 0f [2] 83 3a [2] ad 3a [2] 92 26 }

  condition:
    any of them
}