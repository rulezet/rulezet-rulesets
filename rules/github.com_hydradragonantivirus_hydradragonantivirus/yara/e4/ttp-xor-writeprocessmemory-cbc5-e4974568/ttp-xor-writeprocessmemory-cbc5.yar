rule TTP_XOR_WriteProcessMemory_cbc5 {
  strings:
    $key_cbc5 = { 9c b7 [2] ae 95 [2] a8 a0 [2] 86 a0 [2] b9 bc }

  condition:
    any of them
}