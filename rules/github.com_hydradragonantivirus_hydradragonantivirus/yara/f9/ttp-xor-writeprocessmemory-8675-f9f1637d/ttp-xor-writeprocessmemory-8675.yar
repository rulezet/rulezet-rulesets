rule TTP_XOR_WriteProcessMemory_8675 {
  strings:
    $key_8675 = { d1 07 [2] e3 25 [2] e5 10 [2] cb 10 [2] f4 0c }

  condition:
    any of them
}