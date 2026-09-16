rule TTP_XOR_WriteProcessMemory_de37 {
  strings:
    $key_de37 = { 89 45 [2] bb 67 [2] bd 52 [2] 93 52 [2] ac 4e }

  condition:
    any of them
}