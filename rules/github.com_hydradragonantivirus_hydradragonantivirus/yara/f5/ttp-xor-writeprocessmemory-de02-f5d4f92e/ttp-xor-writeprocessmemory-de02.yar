rule TTP_XOR_WriteProcessMemory_de02 {
  strings:
    $key_de02 = { 89 70 [2] bb 52 [2] bd 67 [2] 93 67 [2] ac 7b }

  condition:
    any of them
}