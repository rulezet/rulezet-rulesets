rule TTP_XOR_WriteProcessMemory_c905 {
  strings:
    $key_c905 = { 9e 77 [2] ac 55 [2] aa 60 [2] 84 60 [2] bb 7c }

  condition:
    any of them
}