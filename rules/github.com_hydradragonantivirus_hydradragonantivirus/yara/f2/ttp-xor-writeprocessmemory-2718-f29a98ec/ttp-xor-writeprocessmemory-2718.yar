rule TTP_XOR_WriteProcessMemory_2718 {
  strings:
    $key_2718 = { 70 6a [2] 42 48 [2] 44 7d [2] 6a 7d [2] 55 61 }

  condition:
    any of them
}