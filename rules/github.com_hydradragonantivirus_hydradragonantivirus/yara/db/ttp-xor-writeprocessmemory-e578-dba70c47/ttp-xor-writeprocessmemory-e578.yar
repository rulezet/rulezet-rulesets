rule TTP_XOR_WriteProcessMemory_e578 {
  strings:
    $key_e578 = { b2 0a [2] 80 28 [2] 86 1d [2] a8 1d [2] 97 01 }

  condition:
    any of them
}