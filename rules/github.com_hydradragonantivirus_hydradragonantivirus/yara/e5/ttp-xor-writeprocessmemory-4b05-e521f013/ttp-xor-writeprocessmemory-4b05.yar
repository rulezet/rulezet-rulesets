rule TTP_XOR_WriteProcessMemory_4b05 {
  strings:
    $key_4b05 = { 1c 77 [2] 2e 55 [2] 28 60 [2] 06 60 [2] 39 7c }

  condition:
    any of them
}