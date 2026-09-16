rule TTP_XOR_WriteProcessMemory_04b2 {
  strings:
    $key_04b2 = { 53 c0 [2] 61 e2 [2] 67 d7 [2] 49 d7 [2] 76 cb }

  condition:
    any of them
}