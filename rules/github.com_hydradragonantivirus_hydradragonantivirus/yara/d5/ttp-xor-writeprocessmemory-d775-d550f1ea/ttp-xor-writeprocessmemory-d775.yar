rule TTP_XOR_WriteProcessMemory_d775 {
  strings:
    $key_d775 = { 80 07 [2] b2 25 [2] b4 10 [2] 9a 10 [2] a5 0c }

  condition:
    any of them
}