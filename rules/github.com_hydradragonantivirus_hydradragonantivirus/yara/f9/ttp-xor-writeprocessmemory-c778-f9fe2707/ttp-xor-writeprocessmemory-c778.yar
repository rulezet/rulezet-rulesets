rule TTP_XOR_WriteProcessMemory_c778 {
  strings:
    $key_c778 = { 90 0a [2] a2 28 [2] a4 1d [2] 8a 1d [2] b5 01 }

  condition:
    any of them
}