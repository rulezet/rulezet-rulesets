rule TTP_XOR_WriteProcessMemory_2b35 {
  strings:
    $key_2b35 = { 7c 47 [2] 4e 65 [2] 48 50 [2] 66 50 [2] 59 4c }

  condition:
    any of them
}