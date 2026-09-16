rule TTP_XOR_WriteProcessMemory_de25 {
  strings:
    $key_de25 = { 89 57 [2] bb 75 [2] bd 40 [2] 93 40 [2] ac 5c }

  condition:
    any of them
}