rule TTP_XOR_WriteProcessMemory_3721 {
  strings:
    $key_3721 = { 60 53 [2] 52 71 [2] 54 44 [2] 7a 44 [2] 45 58 }

  condition:
    any of them
}