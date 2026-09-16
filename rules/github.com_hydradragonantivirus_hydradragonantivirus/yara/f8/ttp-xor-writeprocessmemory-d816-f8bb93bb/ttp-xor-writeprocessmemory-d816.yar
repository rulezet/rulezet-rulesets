rule TTP_XOR_WriteProcessMemory_d816 {
  strings:
    $key_d816 = { 8f 64 [2] bd 46 [2] bb 73 [2] 95 73 [2] aa 6f }

  condition:
    any of them
}