rule TTP_XOR_WriteProcessMemory_2c45 {
  strings:
    $key_2c45 = { 7b 37 [2] 49 15 [2] 4f 20 [2] 61 20 [2] 5e 3c }

  condition:
    any of them
}