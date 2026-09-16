rule TTP_XOR_WriteProcessMemory_efd6 {
  strings:
    $key_efd6 = { b8 a4 [2] 8a 86 [2] 8c b3 [2] a2 b3 [2] 9d af }

  condition:
    any of them
}