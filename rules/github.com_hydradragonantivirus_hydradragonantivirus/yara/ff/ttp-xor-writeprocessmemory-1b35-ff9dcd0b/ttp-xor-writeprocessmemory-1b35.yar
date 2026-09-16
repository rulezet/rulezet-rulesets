rule TTP_XOR_WriteProcessMemory_1b35 {
  strings:
    $key_1b35 = { 4c 47 [2] 7e 65 [2] 78 50 [2] 56 50 [2] 69 4c }

  condition:
    any of them
}