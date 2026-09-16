rule TTP_XOR_WriteProcessMemory_d178 {
  strings:
    $key_d178 = { 86 0a [2] b4 28 [2] b2 1d [2] 9c 1d [2] a3 01 }

  condition:
    any of them
}