rule TTP_XOR_WriteProcessMemory_03f1 {
  strings:
    $key_03f1 = { 54 83 [2] 66 a1 [2] 60 94 [2] 4e 94 [2] 71 88 }

  condition:
    any of them
}