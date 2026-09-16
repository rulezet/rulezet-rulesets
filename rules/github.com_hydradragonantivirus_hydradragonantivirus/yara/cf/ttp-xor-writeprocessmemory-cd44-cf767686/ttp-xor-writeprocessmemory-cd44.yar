rule TTP_XOR_WriteProcessMemory_cd44 {
  strings:
    $key_cd44 = { 9a 36 [2] a8 14 [2] ae 21 [2] 80 21 [2] bf 3d }

  condition:
    any of them
}