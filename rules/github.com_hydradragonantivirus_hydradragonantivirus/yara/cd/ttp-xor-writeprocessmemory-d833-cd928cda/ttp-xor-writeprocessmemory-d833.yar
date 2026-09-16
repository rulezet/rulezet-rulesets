rule TTP_XOR_WriteProcessMemory_d833 {
  strings:
    $key_d833 = { 8f 41 [2] bd 63 [2] bb 56 [2] 95 56 [2] aa 4a }

  condition:
    any of them
}