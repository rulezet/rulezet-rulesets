rule TTP_XOR_WriteProcessMemory_de83 {
  strings:
    $key_de83 = { 89 f1 [2] bb d3 [2] bd e6 [2] 93 e6 [2] ac fa }

  condition:
    any of them
}