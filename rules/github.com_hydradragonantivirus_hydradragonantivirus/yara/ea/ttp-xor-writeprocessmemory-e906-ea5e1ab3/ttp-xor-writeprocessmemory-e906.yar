rule TTP_XOR_WriteProcessMemory_e906 {
  strings:
    $key_e906 = { be 74 [2] 8c 56 [2] 8a 63 [2] a4 63 [2] 9b 7f }

  condition:
    any of them
}