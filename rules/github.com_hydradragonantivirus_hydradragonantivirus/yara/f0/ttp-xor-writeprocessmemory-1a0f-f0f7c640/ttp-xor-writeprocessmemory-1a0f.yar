rule TTP_XOR_WriteProcessMemory_1a0f {
  strings:
    $key_1a0f = { 4d 7d [2] 7f 5f [2] 79 6a [2] 57 6a [2] 68 76 }

  condition:
    any of them
}