rule TTP_XOR_WriteProcessMemory_d8d2 {
  strings:
    $key_d8d2 = { 8f a0 [2] bd 82 [2] bb b7 [2] 95 b7 [2] aa ab }

  condition:
    any of them
}