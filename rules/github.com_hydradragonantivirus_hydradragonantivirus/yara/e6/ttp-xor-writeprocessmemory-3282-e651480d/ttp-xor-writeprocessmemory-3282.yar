rule TTP_XOR_WriteProcessMemory_3282 {
  strings:
    $key_3282 = { 65 f0 [2] 57 d2 [2] 51 e7 [2] 7f e7 [2] 40 fb }

  condition:
    any of them
}