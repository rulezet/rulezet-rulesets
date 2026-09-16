rule TTP_XOR_WriteProcessMemory_635f {
  strings:
    $key_635f = { 34 2d [2] 06 0f [2] 00 3a [2] 2e 3a [2] 11 26 }

  condition:
    any of them
}