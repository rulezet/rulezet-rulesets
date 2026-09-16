rule TTP_XOR_WriteProcessMemory_6b97 {
  strings:
    $key_6b97 = { 3c e5 [2] 0e c7 [2] 08 f2 [2] 26 f2 [2] 19 ee }

  condition:
    any of them
}