rule TTP_XOR_WriteProcessMemory_d8d5 {
  strings:
    $key_d8d5 = { 8f a7 [2] bd 85 [2] bb b0 [2] 95 b0 [2] aa ac }

  condition:
    any of them
}