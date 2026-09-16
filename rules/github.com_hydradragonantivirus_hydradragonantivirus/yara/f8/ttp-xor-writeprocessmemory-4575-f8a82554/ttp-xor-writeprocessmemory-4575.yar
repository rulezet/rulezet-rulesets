rule TTP_XOR_WriteProcessMemory_4575 {
  strings:
    $key_4575 = { 12 07 [2] 20 25 [2] 26 10 [2] 08 10 [2] 37 0c }

  condition:
    any of them
}