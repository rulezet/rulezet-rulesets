rule TTP_XOR_WriteProcessMemory_e25f {
  strings:
    $key_e25f = { b5 2d [2] 87 0f [2] 81 3a [2] af 3a [2] 90 26 }

  condition:
    any of them
}