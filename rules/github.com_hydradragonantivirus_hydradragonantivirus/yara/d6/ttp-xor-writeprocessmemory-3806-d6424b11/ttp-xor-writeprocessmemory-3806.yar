rule TTP_XOR_WriteProcessMemory_3806 {
  strings:
    $key_3806 = { 6f 74 [2] 5d 56 [2] 5b 63 [2] 75 63 [2] 4a 7f }

  condition:
    any of them
}