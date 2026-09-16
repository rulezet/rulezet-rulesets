rule TTP_XOR_WriteProcessMemory_6227 {
  strings:
    $key_6227 = { 35 55 [2] 07 77 [2] 01 42 [2] 2f 42 [2] 10 5e }

  condition:
    any of them
}