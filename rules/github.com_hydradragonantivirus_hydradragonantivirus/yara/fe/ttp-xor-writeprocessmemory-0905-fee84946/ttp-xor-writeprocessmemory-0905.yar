rule TTP_XOR_WriteProcessMemory_0905 {
  strings:
    $key_0905 = { 5e 77 [2] 6c 55 [2] 6a 60 [2] 44 60 [2] 7b 7c }

  condition:
    any of them
}