rule TTP_XOR_WriteProcessMemory_d677 {
  strings:
    $key_d677 = { 81 05 [2] b3 27 [2] b5 12 [2] 9b 12 [2] a4 0e }

  condition:
    any of them
}