rule TTP_XOR_WriteProcessMemory_0a5f {
  strings:
    $key_0a5f = { 5d 2d [2] 6f 0f [2] 69 3a [2] 47 3a [2] 78 26 }

  condition:
    any of them
}