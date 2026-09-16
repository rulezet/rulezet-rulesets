rule TTP_XOR_WriteProcessMemory_55b2 {
  strings:
    $key_55b2 = { 02 c0 [2] 30 e2 [2] 36 d7 [2] 18 d7 [2] 27 cb }

  condition:
    any of them
}