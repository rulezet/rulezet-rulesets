rule TTP_XOR_WriteProcessMemory_2c15 {
  strings:
    $key_2c15 = { 7b 67 [2] 49 45 [2] 4f 70 [2] 61 70 [2] 5e 6c }

  condition:
    any of them
}