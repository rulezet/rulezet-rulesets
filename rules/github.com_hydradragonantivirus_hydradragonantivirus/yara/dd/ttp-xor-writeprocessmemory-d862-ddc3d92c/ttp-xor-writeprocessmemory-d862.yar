rule TTP_XOR_WriteProcessMemory_d862 {
  strings:
    $key_d862 = { 8f 10 [2] bd 32 [2] bb 07 [2] 95 07 [2] aa 1b }

  condition:
    any of them
}