rule TTP_XOR_WriteProcessMemory_26a3 {
  strings:
    $key_26a3 = { 71 d1 [2] 43 f3 [2] 45 c6 [2] 6b c6 [2] 54 da }

  condition:
    any of them
}