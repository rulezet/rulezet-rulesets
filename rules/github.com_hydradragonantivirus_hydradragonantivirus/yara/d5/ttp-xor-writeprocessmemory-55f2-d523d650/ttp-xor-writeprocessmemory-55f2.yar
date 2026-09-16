rule TTP_XOR_WriteProcessMemory_55f2 {
  strings:
    $key_55f2 = { 02 80 [2] 30 a2 [2] 36 97 [2] 18 97 [2] 27 8b }

  condition:
    any of them
}