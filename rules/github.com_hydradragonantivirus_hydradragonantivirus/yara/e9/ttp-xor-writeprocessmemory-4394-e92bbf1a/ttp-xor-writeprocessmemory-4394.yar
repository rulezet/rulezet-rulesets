rule TTP_XOR_WriteProcessMemory_4394 {
  strings:
    $key_4394 = { 14 e6 [2] 26 c4 [2] 20 f1 [2] 0e f1 [2] 31 ed }

  condition:
    any of them
}