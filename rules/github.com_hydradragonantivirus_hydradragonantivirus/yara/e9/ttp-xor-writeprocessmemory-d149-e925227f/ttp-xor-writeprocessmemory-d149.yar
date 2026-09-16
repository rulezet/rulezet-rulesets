rule TTP_XOR_WriteProcessMemory_d149 {
  strings:
    $key_d149 = { 86 3b [2] b4 19 [2] b2 2c [2] 9c 2c [2] a3 30 }

  condition:
    any of them
}