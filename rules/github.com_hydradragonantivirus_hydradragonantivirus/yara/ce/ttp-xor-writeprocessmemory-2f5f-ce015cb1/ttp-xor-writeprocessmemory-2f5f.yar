rule TTP_XOR_WriteProcessMemory_2f5f {
  strings:
    $key_2f5f = { 78 2d [2] 4a 0f [2] 4c 3a [2] 62 3a [2] 5d 26 }

  condition:
    any of them
}