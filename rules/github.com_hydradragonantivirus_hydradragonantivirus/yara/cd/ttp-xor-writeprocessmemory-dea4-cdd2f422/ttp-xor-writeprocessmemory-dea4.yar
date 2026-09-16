rule TTP_XOR_WriteProcessMemory_dea4 {
  strings:
    $key_dea4 = { 89 d6 [2] bb f4 [2] bd c1 [2] 93 c1 [2] ac dd }

  condition:
    any of them
}