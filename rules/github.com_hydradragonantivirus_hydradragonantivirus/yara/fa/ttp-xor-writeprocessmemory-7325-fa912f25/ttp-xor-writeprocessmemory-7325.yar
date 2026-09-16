rule TTP_XOR_WriteProcessMemory_7325 {
  strings:
    $key_7325 = { 24 57 [2] 16 75 [2] 10 40 [2] 3e 40 [2] 01 5c }

  condition:
    any of them
}