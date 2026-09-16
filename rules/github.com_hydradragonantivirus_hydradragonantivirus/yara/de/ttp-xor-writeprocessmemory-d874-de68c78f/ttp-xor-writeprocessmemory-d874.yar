rule TTP_XOR_WriteProcessMemory_d874 {
  strings:
    $key_d874 = { 8f 06 [2] bd 24 [2] bb 11 [2] 95 11 [2] aa 0d }

  condition:
    any of them
}