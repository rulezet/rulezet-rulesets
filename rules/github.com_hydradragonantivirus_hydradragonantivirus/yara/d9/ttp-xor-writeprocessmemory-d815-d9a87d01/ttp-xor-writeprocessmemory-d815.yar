rule TTP_XOR_WriteProcessMemory_d815 {
  strings:
    $key_d815 = { 8f 67 [2] bd 45 [2] bb 70 [2] 95 70 [2] aa 6c }

  condition:
    any of them
}