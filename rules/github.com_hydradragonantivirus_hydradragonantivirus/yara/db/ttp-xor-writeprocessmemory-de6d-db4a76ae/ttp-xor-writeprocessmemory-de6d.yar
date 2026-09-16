rule TTP_XOR_WriteProcessMemory_de6d {
  strings:
    $key_de6d = { 89 1f [2] bb 3d [2] bd 08 [2] 93 08 [2] ac 14 }

  condition:
    any of them
}