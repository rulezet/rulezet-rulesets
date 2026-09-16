rule TTP_XOR_WriteProcessMemory_3205 {
  strings:
    $key_3205 = { 65 77 [2] 57 55 [2] 51 60 [2] 7f 60 [2] 40 7c }

  condition:
    any of them
}