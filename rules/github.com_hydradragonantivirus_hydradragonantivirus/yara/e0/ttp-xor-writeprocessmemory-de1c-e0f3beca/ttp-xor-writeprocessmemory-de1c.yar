rule TTP_XOR_WriteProcessMemory_de1c {
  strings:
    $key_de1c = { 89 6e [2] bb 4c [2] bd 79 [2] 93 79 [2] ac 65 }

  condition:
    any of them
}