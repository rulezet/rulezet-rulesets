rule TTP_XOR_WriteProcessMemory_6e82 {
  strings:
    $key_6e82 = { 39 f0 [2] 0b d2 [2] 0d e7 [2] 23 e7 [2] 1c fb }

  condition:
    any of them
}