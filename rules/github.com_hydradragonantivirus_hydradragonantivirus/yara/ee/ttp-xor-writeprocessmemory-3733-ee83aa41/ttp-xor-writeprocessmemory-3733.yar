rule TTP_XOR_WriteProcessMemory_3733 {
  strings:
    $key_3733 = { 60 41 [2] 52 63 [2] 54 56 [2] 7a 56 [2] 45 4a }

  condition:
    any of them
}