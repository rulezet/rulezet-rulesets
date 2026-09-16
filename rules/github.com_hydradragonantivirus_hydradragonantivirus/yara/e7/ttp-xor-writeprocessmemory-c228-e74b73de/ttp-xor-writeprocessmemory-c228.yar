rule TTP_XOR_WriteProcessMemory_c228 {
  strings:
    $key_c228 = { 95 5a [2] a7 78 [2] a1 4d [2] 8f 4d [2] b0 51 }

  condition:
    any of them
}