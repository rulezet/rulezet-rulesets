rule TTP_XOR_WriteProcessMemory_d8c6 {
  strings:
    $key_d8c6 = { 8f b4 [2] bd 96 [2] bb a3 [2] 95 a3 [2] aa bf }

  condition:
    any of them
}