rule TTP_XOR_WriteProcessMemory_34b2 {
  strings:
    $key_34b2 = { 63 c0 [2] 51 e2 [2] 57 d7 [2] 79 d7 [2] 46 cb }

  condition:
    any of them
}