rule TTP_XOR_WriteProcessMemory_7891 {
  strings:
    $key_7891 = { 2f e3 [2] 1d c1 [2] 1b f4 [2] 35 f4 [2] 0a e8 }

  condition:
    any of them
}