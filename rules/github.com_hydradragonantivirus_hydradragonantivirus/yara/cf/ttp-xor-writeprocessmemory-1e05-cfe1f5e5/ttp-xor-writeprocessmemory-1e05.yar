rule TTP_XOR_WriteProcessMemory_1e05 {
  strings:
    $key_1e05 = { 49 77 [2] 7b 55 [2] 7d 60 [2] 53 60 [2] 6c 7c }

  condition:
    any of them
}