rule TTP_XOR_WriteProcessMemory_0ce5 {
  strings:
    $key_0ce5 = { 5b 97 [2] 69 b5 [2] 6f 80 [2] 41 80 [2] 7e 9c }

  condition:
    any of them
}