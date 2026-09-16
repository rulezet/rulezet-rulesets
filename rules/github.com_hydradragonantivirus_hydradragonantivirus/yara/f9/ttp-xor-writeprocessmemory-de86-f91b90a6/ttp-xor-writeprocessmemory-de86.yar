rule TTP_XOR_WriteProcessMemory_de86 {
  strings:
    $key_de86 = { 89 f4 [2] bb d6 [2] bd e3 [2] 93 e3 [2] ac ff }

  condition:
    any of them
}