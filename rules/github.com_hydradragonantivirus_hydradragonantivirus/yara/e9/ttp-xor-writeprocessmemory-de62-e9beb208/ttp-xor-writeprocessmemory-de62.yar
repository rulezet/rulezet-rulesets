rule TTP_XOR_WriteProcessMemory_de62 {
  strings:
    $key_de62 = { 89 10 [2] bb 32 [2] bd 07 [2] 93 07 [2] ac 1b }

  condition:
    any of them
}