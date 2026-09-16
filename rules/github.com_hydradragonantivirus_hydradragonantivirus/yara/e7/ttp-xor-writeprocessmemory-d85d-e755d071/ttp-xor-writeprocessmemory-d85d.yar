rule TTP_XOR_WriteProcessMemory_d85d {
  strings:
    $key_d85d = { 8f 2f [2] bd 0d [2] bb 38 [2] 95 38 [2] aa 24 }

  condition:
    any of them
}