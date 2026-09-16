rule TTP_XOR_WriteProcessMemory_de58 {
  strings:
    $key_de58 = { 89 2a [2] bb 08 [2] bd 3d [2] 93 3d [2] ac 21 }

  condition:
    any of them
}