rule TTP_XOR_WriteProcessMemory_d839 {
  strings:
    $key_d839 = { 8f 4b [2] bd 69 [2] bb 5c [2] 95 5c [2] aa 40 }

  condition:
    any of them
}