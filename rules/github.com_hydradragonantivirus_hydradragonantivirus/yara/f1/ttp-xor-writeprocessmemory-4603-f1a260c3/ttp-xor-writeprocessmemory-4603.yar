rule TTP_XOR_WriteProcessMemory_4603 {
  strings:
    $key_4603 = { 11 71 [2] 23 53 [2] 25 66 [2] 0b 66 [2] 34 7a }

  condition:
    any of them
}