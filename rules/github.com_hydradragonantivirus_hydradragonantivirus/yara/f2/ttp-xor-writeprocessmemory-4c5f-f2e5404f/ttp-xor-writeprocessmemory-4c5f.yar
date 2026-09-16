rule TTP_XOR_WriteProcessMemory_4c5f {
  strings:
    $key_4c5f = { 1b 2d [2] 29 0f [2] 2f 3a [2] 01 3a [2] 3e 26 }

  condition:
    any of them
}