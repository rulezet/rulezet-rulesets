rule TTP_XOR_WriteProcessMemory_0675 {
  strings:
    $key_0675 = { 51 07 [2] 63 25 [2] 65 10 [2] 4b 10 [2] 74 0c }

  condition:
    any of them
}