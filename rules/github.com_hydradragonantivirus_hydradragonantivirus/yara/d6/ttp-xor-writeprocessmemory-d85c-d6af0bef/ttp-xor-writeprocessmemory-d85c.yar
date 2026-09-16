rule TTP_XOR_WriteProcessMemory_d85c {
  strings:
    $key_d85c = { 8f 2e [2] bd 0c [2] bb 39 [2] 95 39 [2] aa 25 }

  condition:
    any of them
}