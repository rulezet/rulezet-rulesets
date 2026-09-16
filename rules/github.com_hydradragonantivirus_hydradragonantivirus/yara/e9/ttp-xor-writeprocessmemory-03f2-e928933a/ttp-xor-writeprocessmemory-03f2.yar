rule TTP_XOR_WriteProcessMemory_03f2 {
  strings:
    $key_03f2 = { 54 80 [2] 66 a2 [2] 60 97 [2] 4e 97 [2] 71 8b }

  condition:
    any of them
}