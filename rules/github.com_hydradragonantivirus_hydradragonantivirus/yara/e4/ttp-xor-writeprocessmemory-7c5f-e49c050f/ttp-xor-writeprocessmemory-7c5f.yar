rule TTP_XOR_WriteProcessMemory_7c5f {
  strings:
    $key_7c5f = { 2b 2d [2] 19 0f [2] 1f 3a [2] 31 3a [2] 0e 26 }

  condition:
    any of them
}