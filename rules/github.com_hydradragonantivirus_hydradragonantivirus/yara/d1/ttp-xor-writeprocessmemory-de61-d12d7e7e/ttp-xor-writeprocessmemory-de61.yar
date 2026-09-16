rule TTP_XOR_WriteProcessMemory_de61 {
  strings:
    $key_de61 = { 89 13 [2] bb 31 [2] bd 04 [2] 93 04 [2] ac 18 }

  condition:
    any of them
}