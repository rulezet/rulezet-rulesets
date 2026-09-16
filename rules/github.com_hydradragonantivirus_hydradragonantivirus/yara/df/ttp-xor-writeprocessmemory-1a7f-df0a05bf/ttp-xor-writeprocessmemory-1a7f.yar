rule TTP_XOR_WriteProcessMemory_1a7f {
  strings:
    $key_1a7f = { 4d 0d [2] 7f 2f [2] 79 1a [2] 57 1a [2] 68 06 }

  condition:
    any of them
}