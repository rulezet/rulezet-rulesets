rule TTP_XOR_WriteProcessMemory_d649 {
  strings:
    $key_d649 = { 81 3b [2] b3 19 [2] b5 2c [2] 9b 2c [2] a4 30 }

  condition:
    any of them
}