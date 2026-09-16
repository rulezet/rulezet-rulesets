rule TTP_XOR_WriteProcessMemory_f05f {
  strings:
    $key_f05f = { a7 2d [2] 95 0f [2] 93 3a [2] bd 3a [2] 82 26 }

  condition:
    any of them
}