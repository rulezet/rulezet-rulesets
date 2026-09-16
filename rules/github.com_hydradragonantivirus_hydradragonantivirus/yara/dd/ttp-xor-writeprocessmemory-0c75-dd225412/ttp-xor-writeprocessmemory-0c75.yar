rule TTP_XOR_WriteProcessMemory_0c75 {
  strings:
    $key_0c75 = { 5b 07 [2] 69 25 [2] 6f 10 [2] 41 10 [2] 7e 0c }

  condition:
    any of them
}