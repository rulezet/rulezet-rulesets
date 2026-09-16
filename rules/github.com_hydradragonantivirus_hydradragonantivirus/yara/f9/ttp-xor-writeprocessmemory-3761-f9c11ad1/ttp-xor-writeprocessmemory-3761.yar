rule TTP_XOR_WriteProcessMemory_3761 {
  strings:
    $key_3761 = { 60 13 [2] 52 31 [2] 54 04 [2] 7a 04 [2] 45 18 }

  condition:
    any of them
}