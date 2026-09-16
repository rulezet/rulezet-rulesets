rule TTP_XOR_WriteProcessMemory_075f {
  strings:
    $key_075f = { 50 2d [2] 62 0f [2] 64 3a [2] 4a 3a [2] 75 26 }

  condition:
    any of them
}