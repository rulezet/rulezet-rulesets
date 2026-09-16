rule TTP_XOR_WriteProcessMemory_7eb2 {
  strings:
    $key_7eb2 = { 29 c0 [2] 1b e2 [2] 1d d7 [2] 33 d7 [2] 0c cb }

  condition:
    any of them
}