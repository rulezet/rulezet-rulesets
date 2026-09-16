rule TTP_XOR_WriteProcessMemory_4175 {
  strings:
    $key_4175 = { 16 07 [2] 24 25 [2] 22 10 [2] 0c 10 [2] 33 0c }

  condition:
    any of them
}