rule TTP_XOR_WriteProcessMemory_d85f {
  strings:
    $key_d85f = { 8f 2d [2] bd 0f [2] bb 3a [2] 95 3a [2] aa 26 }

  condition:
    any of them
}