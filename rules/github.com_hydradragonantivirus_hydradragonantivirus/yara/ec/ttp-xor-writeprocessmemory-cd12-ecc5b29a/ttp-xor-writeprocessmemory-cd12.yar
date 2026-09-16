rule TTP_XOR_WriteProcessMemory_cd12 {
  strings:
    $key_cd12 = { 9a 60 [2] a8 42 [2] ae 77 [2] 80 77 [2] bf 6b }

  condition:
    any of them
}