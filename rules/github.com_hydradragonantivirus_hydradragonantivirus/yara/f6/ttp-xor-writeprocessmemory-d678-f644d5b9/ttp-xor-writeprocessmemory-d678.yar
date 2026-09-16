rule TTP_XOR_WriteProcessMemory_d678 {
  strings:
    $key_d678 = { 81 0a [2] b3 28 [2] b5 1d [2] 9b 1d [2] a4 01 }

  condition:
    any of them
}