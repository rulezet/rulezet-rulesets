rule TTP_XOR_WriteProcessMemory_50e3 {
  strings:
    $key_50e3 = { 07 91 [2] 35 b3 [2] 33 86 [2] 1d 86 [2] 22 9a }

  condition:
    any of them
}