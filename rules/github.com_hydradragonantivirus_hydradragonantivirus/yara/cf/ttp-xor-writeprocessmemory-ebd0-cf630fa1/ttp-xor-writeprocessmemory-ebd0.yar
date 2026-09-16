rule TTP_XOR_WriteProcessMemory_ebd0 {
  strings:
    $key_ebd0 = { bc a2 [2] 8e 80 [2] 88 b5 [2] a6 b5 [2] 99 a9 }

  condition:
    any of them
}