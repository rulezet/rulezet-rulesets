rule TTP_XOR_WriteProcessMemory_3214 {
  strings:
    $key_3214 = { 65 66 [2] 57 44 [2] 51 71 [2] 7f 71 [2] 40 6d }

  condition:
    any of them
}