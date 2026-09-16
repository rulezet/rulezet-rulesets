rule TTP_XOR_WriteProcessMemory_4386 {
  strings:
    $key_4386 = { 14 f4 [2] 26 d6 [2] 20 e3 [2] 0e e3 [2] 31 ff }

  condition:
    any of them
}