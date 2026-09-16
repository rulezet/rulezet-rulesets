rule TTP_XOR_WriteProcessMemory_6f87 {
  strings:
    $key_6f87 = { 38 f5 [2] 0a d7 [2] 0c e2 [2] 22 e2 [2] 1d fe }

  condition:
    any of them
}