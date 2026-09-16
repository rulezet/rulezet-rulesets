rule TTP_XOR_WriteProcessMemory_2706 {
  strings:
    $key_2706 = { 70 74 [2] 42 56 [2] 44 63 [2] 6a 63 [2] 55 7f }

  condition:
    any of them
}