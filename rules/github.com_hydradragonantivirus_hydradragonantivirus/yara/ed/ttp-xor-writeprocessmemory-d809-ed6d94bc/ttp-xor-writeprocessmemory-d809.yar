rule TTP_XOR_WriteProcessMemory_d809 {
  strings:
    $key_d809 = { 8f 7b [2] bd 59 [2] bb 6c [2] 95 6c [2] aa 70 }

  condition:
    any of them
}