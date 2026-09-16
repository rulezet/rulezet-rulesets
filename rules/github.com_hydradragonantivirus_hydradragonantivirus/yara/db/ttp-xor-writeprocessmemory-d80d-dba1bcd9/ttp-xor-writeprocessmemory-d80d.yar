rule TTP_XOR_WriteProcessMemory_d80d {
  strings:
    $key_d80d = { 8f 7f [2] bd 5d [2] bb 68 [2] 95 68 [2] aa 74 }

  condition:
    any of them
}