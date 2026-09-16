rule TTP_XOR_WriteProcessMemory_3782 {
  strings:
    $key_3782 = { 60 f0 [2] 52 d2 [2] 54 e7 [2] 7a e7 [2] 45 fb }

  condition:
    any of them
}