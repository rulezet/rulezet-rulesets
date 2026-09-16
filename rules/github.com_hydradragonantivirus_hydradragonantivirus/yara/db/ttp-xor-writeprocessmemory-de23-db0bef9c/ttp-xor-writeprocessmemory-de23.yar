rule TTP_XOR_WriteProcessMemory_de23 {
  strings:
    $key_de23 = { 89 51 [2] bb 73 [2] bd 46 [2] 93 46 [2] ac 5a }

  condition:
    any of them
}