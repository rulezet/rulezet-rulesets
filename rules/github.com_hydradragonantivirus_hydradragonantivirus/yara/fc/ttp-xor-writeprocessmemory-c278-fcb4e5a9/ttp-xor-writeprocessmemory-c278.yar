rule TTP_XOR_WriteProcessMemory_c278 {
  strings:
    $key_c278 = { 95 0a [2] a7 28 [2] a1 1d [2] 8f 1d [2] b0 01 }

  condition:
    any of them
}