rule TTP_XOR_WriteProcessMemory_3c5f {
  strings:
    $key_3c5f = { 6b 2d [2] 59 0f [2] 5f 3a [2] 71 3a [2] 4e 26 }

  condition:
    any of them
}