rule TTP_XOR_WriteProcessMemory_48b3 {
  strings:
    $key_48b3 = { 1f c1 [2] 2d e3 [2] 2b d6 [2] 05 d6 [2] 3a ca }

  condition:
    any of them
}