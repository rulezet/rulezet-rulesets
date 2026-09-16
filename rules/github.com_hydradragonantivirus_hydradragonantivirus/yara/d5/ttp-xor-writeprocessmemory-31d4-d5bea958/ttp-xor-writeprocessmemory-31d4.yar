rule TTP_XOR_WriteProcessMemory_31d4 {
  strings:
    $key_31d4 = { 66 a6 [2] 54 84 [2] 52 b1 [2] 7c b1 [2] 43 ad }

  condition:
    any of them
}