rule TTP_XOR_WriteProcessMemory_a986 {
  strings:
    $key_a986 = { fe f4 [2] cc d6 [2] ca e3 [2] e4 e3 [2] db ff }

  condition:
    any of them
}