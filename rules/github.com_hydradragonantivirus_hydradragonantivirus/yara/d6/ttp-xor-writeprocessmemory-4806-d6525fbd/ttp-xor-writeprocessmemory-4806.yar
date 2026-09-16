rule TTP_XOR_WriteProcessMemory_4806 {
  strings:
    $key_4806 = { 1f 74 [2] 2d 56 [2] 2b 63 [2] 05 63 [2] 3a 7f }

  condition:
    any of them
}