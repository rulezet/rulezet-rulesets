rule TTP_XOR_WriteProcessMemory_c238 {
  strings:
    $key_c238 = { 95 4a [2] a7 68 [2] a1 5d [2] 8f 5d [2] b0 41 }

  condition:
    any of them
}