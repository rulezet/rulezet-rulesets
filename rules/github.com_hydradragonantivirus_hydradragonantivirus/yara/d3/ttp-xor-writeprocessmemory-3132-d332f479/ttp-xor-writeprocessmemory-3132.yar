rule TTP_XOR_WriteProcessMemory_3132 {
  strings:
    $key_3132 = { 66 40 [2] 54 62 [2] 52 57 [2] 7c 57 [2] 43 4b }

  condition:
    any of them
}