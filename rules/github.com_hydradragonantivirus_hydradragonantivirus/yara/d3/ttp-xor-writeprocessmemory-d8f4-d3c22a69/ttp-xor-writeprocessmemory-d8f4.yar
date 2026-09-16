rule TTP_XOR_WriteProcessMemory_d8f4 {
  strings:
    $key_d8f4 = { 8f 86 [2] bd a4 [2] bb 91 [2] 95 91 [2] aa 8d }

  condition:
    any of them
}