rule TTP_XOR_WriteProcessMemory_1f87 {
  strings:
    $key_1f87 = { 48 f5 [2] 7a d7 [2] 7c e2 [2] 52 e2 [2] 6d fe }

  condition:
    any of them
}