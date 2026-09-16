rule TTP_XOR_WriteProcessMemory_e7b2 {
  strings:
    $key_e7b2 = { b0 c0 [2] 82 e2 [2] 84 d7 [2] aa d7 [2] 95 cb }

  condition:
    any of them
}