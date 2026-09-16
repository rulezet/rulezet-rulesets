rule TTP_XOR_WriteProcessMemory_3eb2 {
  strings:
    $key_3eb2 = { 69 c0 [2] 5b e2 [2] 5d d7 [2] 73 d7 [2] 4c cb }

  condition:
    any of them
}