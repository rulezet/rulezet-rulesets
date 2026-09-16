rule TTP_XOR_WriteProcessMemory_f4a5 {
  strings:
    $key_f4a5 = { a3 d7 [2] 91 f5 [2] 97 c0 [2] b9 c0 [2] 86 dc }

  condition:
    any of them
}