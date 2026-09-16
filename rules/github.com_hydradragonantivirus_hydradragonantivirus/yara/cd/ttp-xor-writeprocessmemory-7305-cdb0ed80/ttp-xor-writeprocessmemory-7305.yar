rule TTP_XOR_WriteProcessMemory_7305 {
  strings:
    $key_7305 = { 24 77 [2] 16 55 [2] 10 60 [2] 3e 60 [2] 01 7c }

  condition:
    any of them
}