rule TTP_XOR_WriteProcessMemory_7c25 {
  strings:
    $key_7c25 = { 2b 57 [2] 19 75 [2] 1f 40 [2] 31 40 [2] 0e 5c }

  condition:
    any of them
}