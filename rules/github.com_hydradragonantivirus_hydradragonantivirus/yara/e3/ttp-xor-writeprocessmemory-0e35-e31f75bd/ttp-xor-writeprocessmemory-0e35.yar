rule TTP_XOR_WriteProcessMemory_0e35 {
  strings:
    $key_0e35 = { 59 47 [2] 6b 65 [2] 6d 50 [2] 43 50 [2] 7c 4c }

  condition:
    any of them
}