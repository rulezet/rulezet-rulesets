rule TTP_XOR_WriteProcessMemory_d865 {
  strings:
    $key_d865 = { 8f 17 [2] bd 35 [2] bb 00 [2] 95 00 [2] aa 1c }

  condition:
    any of them
}