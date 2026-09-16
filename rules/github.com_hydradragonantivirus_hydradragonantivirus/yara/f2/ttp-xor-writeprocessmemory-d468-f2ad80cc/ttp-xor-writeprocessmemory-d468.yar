rule TTP_XOR_WriteProcessMemory_d468 {
  strings:
    $key_d468 = { 83 1a [2] b1 38 [2] b7 0d [2] 99 0d [2] a6 11 }

  condition:
    any of them
}