rule TTP_XOR_WriteProcessMemory_5d5f {
  strings:
    $key_5d5f = { 0a 2d [2] 38 0f [2] 3e 3a [2] 10 3a [2] 2f 26 }

  condition:
    any of them
}