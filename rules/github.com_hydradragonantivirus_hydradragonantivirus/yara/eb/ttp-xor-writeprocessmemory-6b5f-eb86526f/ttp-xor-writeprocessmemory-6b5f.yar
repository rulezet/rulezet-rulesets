rule TTP_XOR_WriteProcessMemory_6b5f {
  strings:
    $key_6b5f = { 3c 2d [2] 0e 0f [2] 08 3a [2] 26 3a [2] 19 26 }

  condition:
    any of them
}