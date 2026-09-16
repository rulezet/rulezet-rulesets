rule TTP_XOR_WriteProcessMemory_cde9 {
  strings:
    $key_cde9 = { 9a 9b [2] a8 b9 [2] ae 8c [2] 80 8c [2] bf 90 }

  condition:
    any of them
}