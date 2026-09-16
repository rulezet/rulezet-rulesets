rule TTP_XOR_WriteProcessMemory_d603 {
  strings:
    $key_d603 = { 81 71 [2] b3 53 [2] b5 66 [2] 9b 66 [2] a4 7a }

  condition:
    any of them
}