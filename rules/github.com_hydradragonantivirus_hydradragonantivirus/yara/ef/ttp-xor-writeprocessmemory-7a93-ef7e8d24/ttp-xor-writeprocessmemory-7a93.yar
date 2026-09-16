rule TTP_XOR_WriteProcessMemory_7a93 {
  strings:
    $key_7a93 = { 2d e1 [2] 1f c3 [2] 19 f6 [2] 37 f6 [2] 08 ea }

  condition:
    any of them
}