rule TTP_XOR_WriteProcessMemory_2446 {
  strings:
    $key_2446 = { 73 34 [2] 41 16 [2] 47 23 [2] 69 23 [2] 56 3f }

  condition:
    any of them
}