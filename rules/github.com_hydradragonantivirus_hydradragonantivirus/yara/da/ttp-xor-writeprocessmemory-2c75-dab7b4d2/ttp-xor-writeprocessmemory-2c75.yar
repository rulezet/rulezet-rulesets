rule TTP_XOR_WriteProcessMemory_2c75 {
  strings:
    $key_2c75 = { 7b 07 [2] 49 25 [2] 4f 10 [2] 61 10 [2] 5e 0c }

  condition:
    any of them
}