rule TTP_XOR_WriteProcessMemory_445f {
  strings:
    $key_445f = { 13 2d [2] 21 0f [2] 27 3a [2] 09 3a [2] 36 26 }

  condition:
    any of them
}