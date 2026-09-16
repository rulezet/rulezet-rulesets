rule TTP_XOR_WriteProcessMemory_d575 {
  strings:
    $key_d575 = { 82 07 [2] b0 25 [2] b6 10 [2] 98 10 [2] a7 0c }

  condition:
    any of them
}