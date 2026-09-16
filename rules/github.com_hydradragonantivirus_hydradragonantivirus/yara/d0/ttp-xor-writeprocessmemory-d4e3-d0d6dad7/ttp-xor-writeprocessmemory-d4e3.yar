rule TTP_XOR_WriteProcessMemory_d4e3 {
  strings:
    $key_d4e3 = { 83 91 [2] b1 b3 [2] b7 86 [2] 99 86 [2] a6 9a }

  condition:
    any of them
}