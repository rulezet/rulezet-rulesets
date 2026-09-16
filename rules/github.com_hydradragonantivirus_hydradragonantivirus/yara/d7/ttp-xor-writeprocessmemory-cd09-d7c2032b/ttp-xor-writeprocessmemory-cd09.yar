rule TTP_XOR_WriteProcessMemory_cd09 {
  strings:
    $key_cd09 = { 9a 7b [2] a8 59 [2] ae 6c [2] 80 6c [2] bf 70 }

  condition:
    any of them
}