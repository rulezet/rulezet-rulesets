rule TTP_XOR_WriteProcessMemory_48f2 {
  strings:
    $key_48f2 = { 1f 80 [2] 2d a2 [2] 2b 97 [2] 05 97 [2] 3a 8b }

  condition:
    any of them
}