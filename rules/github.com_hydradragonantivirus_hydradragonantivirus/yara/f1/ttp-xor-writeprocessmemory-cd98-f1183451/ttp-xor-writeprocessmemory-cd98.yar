rule TTP_XOR_WriteProcessMemory_cd98 {
  strings:
    $key_cd98 = { 9a ea [2] a8 c8 [2] ae fd [2] 80 fd [2] bf e1 }

  condition:
    any of them
}