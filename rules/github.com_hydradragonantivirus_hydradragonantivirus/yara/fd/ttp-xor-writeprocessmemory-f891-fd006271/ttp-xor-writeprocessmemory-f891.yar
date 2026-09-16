rule TTP_XOR_WriteProcessMemory_f891 {
  strings:
    $key_f891 = { af e3 [2] 9d c1 [2] 9b f4 [2] b5 f4 [2] 8a e8 }

  condition:
    any of them
}