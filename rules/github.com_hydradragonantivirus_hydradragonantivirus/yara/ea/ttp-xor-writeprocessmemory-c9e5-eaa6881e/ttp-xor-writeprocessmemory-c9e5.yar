rule TTP_XOR_WriteProcessMemory_c9e5 {
  strings:
    $key_c9e5 = { 9e 97 [2] ac b5 [2] aa 80 [2] 84 80 [2] bb 9c }

  condition:
    any of them
}