rule TTP_XOR_WriteProcessMemory_51d7 {
  strings:
    $key_51d7 = { 06 a5 [2] 34 87 [2] 32 b2 [2] 1c b2 [2] 23 ae }

  condition:
    any of them
}