rule TTP_XOR_WriteProcessMemory_cde5 {
  strings:
    $key_cde5 = { 9a 97 [2] a8 b5 [2] ae 80 [2] 80 80 [2] bf 9c }

  condition:
    any of them
}