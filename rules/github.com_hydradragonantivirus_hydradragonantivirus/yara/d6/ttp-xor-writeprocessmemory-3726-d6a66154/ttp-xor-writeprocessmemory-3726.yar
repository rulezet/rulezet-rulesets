rule TTP_XOR_WriteProcessMemory_3726 {
  strings:
    $key_3726 = { 60 54 [2] 52 76 [2] 54 43 [2] 7a 43 [2] 45 5f }

  condition:
    any of them
}