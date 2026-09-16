rule TTP_XOR_WriteProcessMemory_de21 {
  strings:
    $key_de21 = { 89 53 [2] bb 71 [2] bd 44 [2] 93 44 [2] ac 58 }

  condition:
    any of them
}