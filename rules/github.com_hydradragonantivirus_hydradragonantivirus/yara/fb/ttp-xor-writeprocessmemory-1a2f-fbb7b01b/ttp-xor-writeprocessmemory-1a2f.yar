rule TTP_XOR_WriteProcessMemory_1a2f {
  strings:
    $key_1a2f = { 4d 5d [2] 7f 7f [2] 79 4a [2] 57 4a [2] 68 56 }

  condition:
    any of them
}