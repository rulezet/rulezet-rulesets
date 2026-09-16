rule TTP_XOR_WriteProcessMemory_05b2 {
  strings:
    $key_05b2 = { 52 c0 [2] 60 e2 [2] 66 d7 [2] 48 d7 [2] 77 cb }

  condition:
    any of them
}