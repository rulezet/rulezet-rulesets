rule TTP_XOR_WriteProcessMemory_6575 {
  strings:
    $key_6575 = { 32 07 [2] 00 25 [2] 06 10 [2] 28 10 [2] 17 0c }

  condition:
    any of them
}