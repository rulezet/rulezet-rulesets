rule TTP_XOR_WriteProcessMemory_1aa6 {
  strings:
    $key_1aa6 = { 4d d4 [2] 7f f6 [2] 79 c3 [2] 57 c3 [2] 68 df }

  condition:
    any of them
}