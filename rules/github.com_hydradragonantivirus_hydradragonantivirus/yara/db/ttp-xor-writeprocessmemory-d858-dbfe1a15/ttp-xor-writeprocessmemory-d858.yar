rule TTP_XOR_WriteProcessMemory_d858 {
  strings:
    $key_d858 = { 8f 2a [2] bd 08 [2] bb 3d [2] 95 3d [2] aa 21 }

  condition:
    any of them
}