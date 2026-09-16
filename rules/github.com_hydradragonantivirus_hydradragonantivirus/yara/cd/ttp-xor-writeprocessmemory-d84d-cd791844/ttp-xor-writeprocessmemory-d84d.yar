rule TTP_XOR_WriteProcessMemory_d84d {
  strings:
    $key_d84d = { 8f 3f [2] bd 1d [2] bb 28 [2] 95 28 [2] aa 34 }

  condition:
    any of them
}