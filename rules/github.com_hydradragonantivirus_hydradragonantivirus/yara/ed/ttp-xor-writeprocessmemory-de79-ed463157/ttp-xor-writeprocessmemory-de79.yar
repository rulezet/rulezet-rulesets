rule TTP_XOR_WriteProcessMemory_de79 {
  strings:
    $key_de79 = { 89 0b [2] bb 29 [2] bd 1c [2] 93 1c [2] ac 00 }

  condition:
    any of them
}