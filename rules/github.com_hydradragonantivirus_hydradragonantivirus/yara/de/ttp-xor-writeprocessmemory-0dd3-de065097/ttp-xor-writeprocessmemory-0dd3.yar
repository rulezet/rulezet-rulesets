rule TTP_XOR_WriteProcessMemory_0dd3 {
  strings:
    $key_0dd3 = { 5a a1 [2] 68 83 [2] 6e b6 [2] 40 b6 [2] 7f aa }

  condition:
    any of them
}