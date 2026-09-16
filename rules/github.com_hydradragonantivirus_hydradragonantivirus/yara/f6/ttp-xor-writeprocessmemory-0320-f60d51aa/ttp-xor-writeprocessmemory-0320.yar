rule TTP_XOR_WriteProcessMemory_0320 {
  strings:
    $key_0320 = { 54 52 [2] 66 70 [2] 60 45 [2] 4e 45 [2] 71 59 }

  condition:
    any of them
}