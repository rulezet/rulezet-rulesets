rule TTP_XOR_WriteProcessMemory_5fd6 {
  strings:
    $key_5fd6 = { 08 a4 [2] 3a 86 [2] 3c b3 [2] 12 b3 [2] 2d af }

  condition:
    any of them
}