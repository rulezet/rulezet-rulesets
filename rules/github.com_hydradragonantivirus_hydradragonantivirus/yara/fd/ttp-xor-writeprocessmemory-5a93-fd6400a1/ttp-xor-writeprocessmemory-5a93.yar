rule TTP_XOR_WriteProcessMemory_5a93 {
  strings:
    $key_5a93 = { 0d e1 [2] 3f c3 [2] 39 f6 [2] 17 f6 [2] 28 ea }

  condition:
    any of them
}