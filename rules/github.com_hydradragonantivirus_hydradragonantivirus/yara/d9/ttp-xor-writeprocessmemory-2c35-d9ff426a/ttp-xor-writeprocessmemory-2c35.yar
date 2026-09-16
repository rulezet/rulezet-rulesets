rule TTP_XOR_WriteProcessMemory_2c35 {
  strings:
    $key_2c35 = { 7b 47 [2] 49 65 [2] 4f 50 [2] 61 50 [2] 5e 4c }

  condition:
    any of them
}