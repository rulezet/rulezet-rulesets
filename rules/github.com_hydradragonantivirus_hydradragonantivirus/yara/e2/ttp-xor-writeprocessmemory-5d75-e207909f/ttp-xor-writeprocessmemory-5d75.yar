rule TTP_XOR_WriteProcessMemory_5d75 {
  strings:
    $key_5d75 = { 0a 07 [2] 38 25 [2] 3e 10 [2] 10 10 [2] 2f 0c }

  condition:
    any of them
}