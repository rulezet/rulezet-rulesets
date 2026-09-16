rule TTP_XOR_WriteProcessMemory_7275 {
  strings:
    $key_7275 = { 25 07 [2] 17 25 [2] 11 10 [2] 3f 10 [2] 00 0c }

  condition:
    any of them
}