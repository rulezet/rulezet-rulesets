rule TTP_XOR_WriteProcessMemory_3593 {
  strings:
    $key_3593 = { 62 e1 [2] 50 c3 [2] 56 f6 [2] 78 f6 [2] 47 ea }

  condition:
    any of them
}