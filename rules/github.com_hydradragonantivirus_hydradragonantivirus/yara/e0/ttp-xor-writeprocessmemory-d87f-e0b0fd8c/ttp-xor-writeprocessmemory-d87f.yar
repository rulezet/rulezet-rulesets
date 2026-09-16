rule TTP_XOR_WriteProcessMemory_d87f {
  strings:
    $key_d87f = { 8f 0d [2] bd 2f [2] bb 1a [2] 95 1a [2] aa 06 }

  condition:
    any of them
}