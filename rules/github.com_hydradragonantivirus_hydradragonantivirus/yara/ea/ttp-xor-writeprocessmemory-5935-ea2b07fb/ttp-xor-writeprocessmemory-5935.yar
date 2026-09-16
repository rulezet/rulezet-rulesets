rule TTP_XOR_WriteProcessMemory_5935 {
  strings:
    $key_5935 = { 0e 47 [2] 3c 65 [2] 3a 50 [2] 14 50 [2] 2b 4c }

  condition:
    any of them
}