rule TTP_XOR_WriteProcessMemory_c84d {
  strings:
    $key_c84d = { 9f 3f [2] ad 1d [2] ab 28 [2] 85 28 [2] ba 34 }

  condition:
    any of them
}