rule TTP_XOR_WriteProcessMemory_48f3 {
  strings:
    $key_48f3 = { 1f 81 [2] 2d a3 [2] 2b 96 [2] 05 96 [2] 3a 8a }

  condition:
    any of them
}