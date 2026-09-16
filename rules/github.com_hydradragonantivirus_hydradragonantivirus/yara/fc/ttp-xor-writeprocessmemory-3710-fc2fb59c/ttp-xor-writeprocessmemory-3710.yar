rule TTP_XOR_WriteProcessMemory_3710 {
  strings:
    $key_3710 = { 60 62 [2] 52 40 [2] 54 75 [2] 7a 75 [2] 45 69 }

  condition:
    any of them
}