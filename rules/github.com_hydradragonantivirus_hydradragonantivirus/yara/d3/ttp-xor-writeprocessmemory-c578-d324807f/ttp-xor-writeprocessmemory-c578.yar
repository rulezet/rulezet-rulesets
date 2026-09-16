rule TTP_XOR_WriteProcessMemory_c578 {
  strings:
    $key_c578 = { 92 0a [2] a0 28 [2] a6 1d [2] 88 1d [2] b7 01 }

  condition:
    any of them
}