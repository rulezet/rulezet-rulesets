rule TTP_XOR_WriteProcessMemory_dec8 {
  strings:
    $key_dec8 = { 89 ba [2] bb 98 [2] bd ad [2] 93 ad [2] ac b1 }

  condition:
    any of them
}