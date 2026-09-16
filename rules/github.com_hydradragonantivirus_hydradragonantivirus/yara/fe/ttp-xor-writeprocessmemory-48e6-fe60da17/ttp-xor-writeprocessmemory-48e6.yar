rule TTP_XOR_WriteProcessMemory_48e6 {
  strings:
    $key_48e6 = { 1f 94 [2] 2d b6 [2] 2b 83 [2] 05 83 [2] 3a 9f }

  condition:
    any of them
}