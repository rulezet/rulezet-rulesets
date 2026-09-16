rule TTP_XOR_WriteProcessMemory_2c05 {
  strings:
    $key_2c05 = { 7b 77 [2] 49 55 [2] 4f 60 [2] 61 60 [2] 5e 7c }

  condition:
    any of them
}