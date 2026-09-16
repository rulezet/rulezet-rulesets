rule TTP_XOR_WriteProcessMemory_d278 {
  strings:
    $key_d278 = { 85 0a [2] b7 28 [2] b1 1d [2] 9f 1d [2] a0 01 }

  condition:
    any of them
}