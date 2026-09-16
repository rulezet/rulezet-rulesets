rule TTP_XOR_WriteProcessMemory_0626 {
  strings:
    $key_0626 = { 51 54 [2] 63 76 [2] 65 43 [2] 4b 43 [2] 74 5f }

  condition:
    any of them
}