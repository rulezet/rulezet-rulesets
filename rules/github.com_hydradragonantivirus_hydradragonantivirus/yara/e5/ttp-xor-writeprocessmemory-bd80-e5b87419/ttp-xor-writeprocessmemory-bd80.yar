rule TTP_XOR_WriteProcessMemory_bd80 {
  strings:
    $key_bd80 = { ea f2 [2] d8 d0 [2] de e5 [2] f0 e5 [2] cf f9 }

  condition:
    any of them
}