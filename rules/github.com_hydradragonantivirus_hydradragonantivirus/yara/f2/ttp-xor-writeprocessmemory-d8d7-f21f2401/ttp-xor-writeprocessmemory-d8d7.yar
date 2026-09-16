rule TTP_XOR_WriteProcessMemory_d8d7 {
  strings:
    $key_d8d7 = { 8f a5 [2] bd 87 [2] bb b2 [2] 95 b2 [2] aa ae }

  condition:
    any of them
}