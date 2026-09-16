rule TTP_XOR_WriteProcessMemory_5593 {
  strings:
    $key_5593 = { 02 e1 [2] 30 c3 [2] 36 f6 [2] 18 f6 [2] 27 ea }

  condition:
    any of them
}