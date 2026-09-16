rule TTP_XOR_WriteProcessMemory_3f87 {
  strings:
    $key_3f87 = { 68 f5 [2] 5a d7 [2] 5c e2 [2] 72 e2 [2] 4d fe }

  condition:
    any of them
}