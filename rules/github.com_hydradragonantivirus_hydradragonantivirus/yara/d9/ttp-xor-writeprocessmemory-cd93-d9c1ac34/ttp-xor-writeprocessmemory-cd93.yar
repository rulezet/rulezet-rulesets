rule TTP_XOR_WriteProcessMemory_cd93 {
  strings:
    $key_cd93 = { 9a e1 [2] a8 c3 [2] ae f6 [2] 80 f6 [2] bf ea }

  condition:
    any of them
}