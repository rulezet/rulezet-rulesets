rule TTP_XOR_WriteProcessMemory_dea6 {
  strings:
    $key_dea6 = { 89 d4 [2] bb f6 [2] bd c3 [2] 93 c3 [2] ac df }

  condition:
    any of them
}