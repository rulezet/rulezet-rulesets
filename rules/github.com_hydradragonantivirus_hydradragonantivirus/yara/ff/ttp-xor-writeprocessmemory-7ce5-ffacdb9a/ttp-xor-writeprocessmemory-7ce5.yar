rule TTP_XOR_WriteProcessMemory_7ce5 {
  strings:
    $key_7ce5 = { 2b 97 [2] 19 b5 [2] 1f 80 [2] 31 80 [2] 0e 9c }

  condition:
    any of them
}