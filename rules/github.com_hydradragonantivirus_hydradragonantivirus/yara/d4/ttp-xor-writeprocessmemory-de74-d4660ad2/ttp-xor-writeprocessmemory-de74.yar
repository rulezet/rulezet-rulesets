rule TTP_XOR_WriteProcessMemory_de74 {
  strings:
    $key_de74 = { 89 06 [2] bb 24 [2] bd 11 [2] 93 11 [2] ac 0d }

  condition:
    any of them
}