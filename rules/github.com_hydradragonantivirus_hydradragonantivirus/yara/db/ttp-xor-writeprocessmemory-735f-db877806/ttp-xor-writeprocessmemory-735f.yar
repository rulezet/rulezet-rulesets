rule TTP_XOR_WriteProcessMemory_735f {
  strings:
    $key_735f = { 24 2d [2] 16 0f [2] 10 3a [2] 3e 3a [2] 01 26 }

  condition:
    any of them
}