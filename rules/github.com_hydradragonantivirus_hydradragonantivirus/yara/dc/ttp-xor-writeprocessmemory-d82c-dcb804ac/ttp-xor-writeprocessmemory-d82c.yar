rule TTP_XOR_WriteProcessMemory_d82c {
  strings:
    $key_d82c = { 8f 5e [2] bd 7c [2] bb 49 [2] 95 49 [2] aa 55 }

  condition:
    any of them
}