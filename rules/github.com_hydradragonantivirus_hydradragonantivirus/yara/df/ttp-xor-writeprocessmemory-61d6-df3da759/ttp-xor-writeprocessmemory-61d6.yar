rule TTP_XOR_WriteProcessMemory_61d6 {
  strings:
    $key_61d6 = { 36 a4 [2] 04 86 [2] 02 b3 [2] 2c b3 [2] 13 af }

  condition:
    any of them
}