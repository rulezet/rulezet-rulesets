rule TTP_XOR_WriteProcessMemory_cbc4 {
  strings:
    $key_cbc4 = { 9c b6 [2] ae 94 [2] a8 a1 [2] 86 a1 [2] b9 bd }

  condition:
    any of them
}