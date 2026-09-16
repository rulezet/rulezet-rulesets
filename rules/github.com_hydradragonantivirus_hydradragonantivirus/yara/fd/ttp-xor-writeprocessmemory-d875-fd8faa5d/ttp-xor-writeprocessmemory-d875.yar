rule TTP_XOR_WriteProcessMemory_d875 {
  strings:
    $key_d875 = { 8f 07 [2] bd 25 [2] bb 10 [2] 95 10 [2] aa 0c }

  condition:
    any of them
}