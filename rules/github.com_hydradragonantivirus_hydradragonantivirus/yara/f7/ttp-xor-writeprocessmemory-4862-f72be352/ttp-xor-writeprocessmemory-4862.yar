rule TTP_XOR_WriteProcessMemory_4862 {
  strings:
    $key_4862 = { 1f 10 [2] 2d 32 [2] 2b 07 [2] 05 07 [2] 3a 1b }

  condition:
    any of them
}