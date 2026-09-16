rule TTP_XOR_WriteProcessMemory_f75f {
  strings:
    $key_f75f = { a0 2d [2] 92 0f [2] 94 3a [2] ba 3a [2] 85 26 }

  condition:
    any of them
}