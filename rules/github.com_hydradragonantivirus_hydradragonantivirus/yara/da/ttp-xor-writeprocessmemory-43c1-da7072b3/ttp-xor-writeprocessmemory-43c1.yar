rule TTP_XOR_WriteProcessMemory_43c1 {
  strings:
    $key_43c1 = { 14 b3 [2] 26 91 [2] 20 a4 [2] 0e a4 [2] 31 b8 }

  condition:
    any of them
}