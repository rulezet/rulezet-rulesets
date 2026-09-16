rule TTP_XOR_WriteProcessMemory_6875 {
  strings:
    $key_6875 = { 3f 07 [2] 0d 25 [2] 0b 10 [2] 25 10 [2] 1a 0c }

  condition:
    any of them
}