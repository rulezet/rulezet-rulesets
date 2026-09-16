rule TTP_XOR_WriteProcessMemory_d131 {
  strings:
    $key_d131 = { 86 43 [2] b4 61 [2] b2 54 [2] 9c 54 [2] a3 48 }

  condition:
    any of them
}