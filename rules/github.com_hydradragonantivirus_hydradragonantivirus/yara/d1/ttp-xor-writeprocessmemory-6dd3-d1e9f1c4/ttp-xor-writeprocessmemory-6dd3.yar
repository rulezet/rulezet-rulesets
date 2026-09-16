rule TTP_XOR_WriteProcessMemory_6dd3 {
  strings:
    $key_6dd3 = { 3a a1 [2] 08 83 [2] 0e b6 [2] 20 b6 [2] 1f aa }

  condition:
    any of them
}