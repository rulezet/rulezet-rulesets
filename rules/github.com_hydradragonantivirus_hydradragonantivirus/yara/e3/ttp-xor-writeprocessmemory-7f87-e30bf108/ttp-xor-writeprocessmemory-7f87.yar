rule TTP_XOR_WriteProcessMemory_7f87 {
  strings:
    $key_7f87 = { 28 f5 [2] 1a d7 [2] 1c e2 [2] 32 e2 [2] 0d fe }

  condition:
    any of them
}