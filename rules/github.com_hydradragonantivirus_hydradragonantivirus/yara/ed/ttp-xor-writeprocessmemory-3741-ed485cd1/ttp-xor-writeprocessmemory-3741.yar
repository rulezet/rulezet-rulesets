rule TTP_XOR_WriteProcessMemory_3741 {
  strings:
    $key_3741 = { 60 33 [2] 52 11 [2] 54 24 [2] 7a 24 [2] 45 38 }

  condition:
    any of them
}