rule TTP_XOR_WriteProcessMemory_d868 {
  strings:
    $key_d868 = { 8f 1a [2] bd 38 [2] bb 0d [2] 95 0d [2] aa 11 }

  condition:
    any of them
}