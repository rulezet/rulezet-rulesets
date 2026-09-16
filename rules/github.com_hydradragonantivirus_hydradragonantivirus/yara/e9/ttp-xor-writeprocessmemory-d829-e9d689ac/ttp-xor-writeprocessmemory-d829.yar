rule TTP_XOR_WriteProcessMemory_d829 {
  strings:
    $key_d829 = { 8f 5b [2] bd 79 [2] bb 4c [2] 95 4c [2] aa 50 }

  condition:
    any of them
}