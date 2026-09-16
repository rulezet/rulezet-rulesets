rule TTP_XOR_WriteProcessMemory_504d {
  strings:
    $key_504d = { 07 3f [2] 35 1d [2] 33 28 [2] 1d 28 [2] 22 34 }

  condition:
    any of them
}