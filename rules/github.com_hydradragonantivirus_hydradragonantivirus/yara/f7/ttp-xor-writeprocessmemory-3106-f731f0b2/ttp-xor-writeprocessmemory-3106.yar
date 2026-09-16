rule TTP_XOR_WriteProcessMemory_3106 {
  strings:
    $key_3106 = { 66 74 [2] 54 56 [2] 52 63 [2] 7c 63 [2] 43 7f }

  condition:
    any of them
}