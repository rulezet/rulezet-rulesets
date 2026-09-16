rule TTP_XOR_WriteProcessMemory_cd80 {
  strings:
    $key_cd80 = { 9a f2 [2] a8 d0 [2] ae e5 [2] 80 e5 [2] bf f9 }

  condition:
    any of them
}