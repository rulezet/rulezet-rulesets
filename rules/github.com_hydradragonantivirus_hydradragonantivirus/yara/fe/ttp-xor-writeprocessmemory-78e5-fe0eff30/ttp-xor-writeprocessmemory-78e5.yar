rule TTP_XOR_WriteProcessMemory_78e5 {
  strings:
    $key_78e5 = { 2f 97 [2] 1d b5 [2] 1b 80 [2] 35 80 [2] 0a 9c }

  condition:
    any of them
}