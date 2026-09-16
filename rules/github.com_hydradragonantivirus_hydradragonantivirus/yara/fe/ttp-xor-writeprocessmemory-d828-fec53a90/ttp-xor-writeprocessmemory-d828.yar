rule TTP_XOR_WriteProcessMemory_d828 {
  strings:
    $key_d828 = { 8f 5a [2] bd 78 [2] bb 4d [2] 95 4d [2] aa 51 }

  condition:
    any of them
}