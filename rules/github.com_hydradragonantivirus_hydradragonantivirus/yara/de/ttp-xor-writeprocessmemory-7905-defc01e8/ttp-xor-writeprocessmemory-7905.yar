rule TTP_XOR_WriteProcessMemory_7905 {
  strings:
    $key_7905 = { 2e 77 [2] 1c 55 [2] 1a 60 [2] 34 60 [2] 0b 7c }

  condition:
    any of them
}