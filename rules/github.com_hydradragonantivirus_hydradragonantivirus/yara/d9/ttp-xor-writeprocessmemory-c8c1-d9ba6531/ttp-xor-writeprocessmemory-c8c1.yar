rule TTP_XOR_WriteProcessMemory_c8c1 {
  strings:
    $key_c8c1 = { 9f b3 [2] ad 91 [2] ab a4 [2] 85 a4 [2] ba b8 }

  condition:
    any of them
}