rule TTP_XOR_WriteProcessMemory_78b3 {
  strings:
    $key_78b3 = { 2f c1 [2] 1d e3 [2] 1b d6 [2] 35 d6 [2] 0a ca }

  condition:
    any of them
}