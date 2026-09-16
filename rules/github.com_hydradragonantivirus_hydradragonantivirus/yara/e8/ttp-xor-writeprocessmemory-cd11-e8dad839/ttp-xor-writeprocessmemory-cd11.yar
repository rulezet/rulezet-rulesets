rule TTP_XOR_WriteProcessMemory_cd11 {
  strings:
    $key_cd11 = { 9a 63 [2] a8 41 [2] ae 74 [2] 80 74 [2] bf 68 }

  condition:
    any of them
}