rule TTP_XOR_WriteProcessMemory_0fd6 {
  strings:
    $key_0fd6 = { 58 a4 [2] 6a 86 [2] 6c b3 [2] 42 b3 [2] 7d af }

  condition:
    any of them
}