rule TTP_XOR_WriteProcessMemory_0a93 {
  strings:
    $key_0a93 = { 5d e1 [2] 6f c3 [2] 69 f6 [2] 47 f6 [2] 78 ea }

  condition:
    any of them
}