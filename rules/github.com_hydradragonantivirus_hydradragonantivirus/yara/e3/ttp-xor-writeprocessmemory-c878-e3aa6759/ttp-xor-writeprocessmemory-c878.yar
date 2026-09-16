rule TTP_XOR_WriteProcessMemory_c878 {
  strings:
    $key_c878 = { 9f 0a [2] ad 28 [2] ab 1d [2] 85 1d [2] ba 01 }

  condition:
    any of them
}