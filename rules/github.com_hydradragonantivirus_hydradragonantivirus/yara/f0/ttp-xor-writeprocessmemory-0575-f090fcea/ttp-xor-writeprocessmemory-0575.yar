rule TTP_XOR_WriteProcessMemory_0575 {
  strings:
    $key_0575 = { 52 07 [2] 60 25 [2] 66 10 [2] 48 10 [2] 77 0c }

  condition:
    any of them
}