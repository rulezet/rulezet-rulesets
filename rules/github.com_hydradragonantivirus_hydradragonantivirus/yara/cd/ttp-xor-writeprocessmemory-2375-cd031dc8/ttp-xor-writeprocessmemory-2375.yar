rule TTP_XOR_WriteProcessMemory_2375 {
  strings:
    $key_2375 = { 74 07 [2] 46 25 [2] 40 10 [2] 6e 10 [2] 51 0c }

  condition:
    any of them
}