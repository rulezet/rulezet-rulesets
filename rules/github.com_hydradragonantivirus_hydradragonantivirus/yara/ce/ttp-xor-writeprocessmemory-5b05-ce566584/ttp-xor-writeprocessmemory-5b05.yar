rule TTP_XOR_WriteProcessMemory_5b05 {
  strings:
    $key_5b05 = { 0c 77 [2] 3e 55 [2] 38 60 [2] 16 60 [2] 29 7c }

  condition:
    any of them
}