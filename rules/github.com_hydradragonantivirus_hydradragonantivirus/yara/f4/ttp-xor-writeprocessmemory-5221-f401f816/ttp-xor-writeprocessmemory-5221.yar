rule TTP_XOR_WriteProcessMemory_5221 {
  strings:
    $key_5221 = { 05 53 [2] 37 71 [2] 31 44 [2] 1f 44 [2] 20 58 }

  condition:
    any of them
}