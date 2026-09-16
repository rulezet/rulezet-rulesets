rule TTP_XOR_WriteProcessMemory_1a6f {
  strings:
    $key_1a6f = { 4d 1d [2] 7f 3f [2] 79 0a [2] 57 0a [2] 68 16 }

  condition:
    any of them
}