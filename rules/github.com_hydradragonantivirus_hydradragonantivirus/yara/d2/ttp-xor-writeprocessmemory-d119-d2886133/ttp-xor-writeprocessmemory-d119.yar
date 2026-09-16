rule TTP_XOR_WriteProcessMemory_d119 {
  strings:
    $key_d119 = { 86 6b [2] b4 49 [2] b2 7c [2] 9c 7c [2] a3 60 }

  condition:
    any of them
}