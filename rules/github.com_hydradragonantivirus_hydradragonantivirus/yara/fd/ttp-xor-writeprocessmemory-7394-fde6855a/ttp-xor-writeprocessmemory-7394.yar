rule TTP_XOR_WriteProcessMemory_7394 {
  strings:
    $key_7394 = { 24 e6 [2] 16 c4 [2] 10 f1 [2] 3e f1 [2] 01 ed }

  condition:
    any of them
}