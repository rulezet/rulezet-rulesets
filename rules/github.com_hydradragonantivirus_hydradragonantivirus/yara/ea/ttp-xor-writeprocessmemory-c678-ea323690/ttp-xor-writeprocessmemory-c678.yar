rule TTP_XOR_WriteProcessMemory_c678 {
  strings:
    $key_c678 = { 91 0a [2] a3 28 [2] a5 1d [2] 8b 1d [2] b4 01 }

  condition:
    any of them
}