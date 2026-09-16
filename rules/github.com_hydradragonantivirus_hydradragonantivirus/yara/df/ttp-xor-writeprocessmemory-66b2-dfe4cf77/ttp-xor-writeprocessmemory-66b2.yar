rule TTP_XOR_WriteProcessMemory_66b2 {
  strings:
    $key_66b2 = { 31 c0 [2] 03 e2 [2] 05 d7 [2] 2b d7 [2] 14 cb }

  condition:
    any of them
}