rule TTP_XOR_WriteProcessMemory_14b2 {
  strings:
    $key_14b2 = { 43 c0 [2] 71 e2 [2] 77 d7 [2] 59 d7 [2] 66 cb }

  condition:
    any of them
}