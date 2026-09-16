rule TTP_XOR_WriteProcessMemory_d817 {
  strings:
    $key_d817 = { 8f 65 [2] bd 47 [2] bb 72 [2] 95 72 [2] aa 6e }

  condition:
    any of them
}