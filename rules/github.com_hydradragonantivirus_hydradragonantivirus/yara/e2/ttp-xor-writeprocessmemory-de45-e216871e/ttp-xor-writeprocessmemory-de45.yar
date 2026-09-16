rule TTP_XOR_WriteProcessMemory_de45 {
  strings:
    $key_de45 = { 89 37 [2] bb 15 [2] bd 20 [2] 93 20 [2] ac 3c }

  condition:
    any of them
}