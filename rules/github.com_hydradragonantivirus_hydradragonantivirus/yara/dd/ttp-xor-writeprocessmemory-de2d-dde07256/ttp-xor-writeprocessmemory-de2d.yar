rule TTP_XOR_WriteProcessMemory_de2d {
  strings:
    $key_de2d = { 89 5f [2] bb 7d [2] bd 48 [2] 93 48 [2] ac 54 }

  condition:
    any of them
}