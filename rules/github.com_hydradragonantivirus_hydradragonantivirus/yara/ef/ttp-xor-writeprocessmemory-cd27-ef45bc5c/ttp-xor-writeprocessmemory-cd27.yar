rule TTP_XOR_WriteProcessMemory_cd27 {
  strings:
    $key_cd27 = { 9a 55 [2] a8 77 [2] ae 42 [2] 80 42 [2] bf 5e }

  condition:
    any of them
}