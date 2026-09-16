rule TTP_XOR_WriteProcessMemory_d870 {
  strings:
    $key_d870 = { 8f 02 [2] bd 20 [2] bb 15 [2] 95 15 [2] aa 09 }

  condition:
    any of them
}