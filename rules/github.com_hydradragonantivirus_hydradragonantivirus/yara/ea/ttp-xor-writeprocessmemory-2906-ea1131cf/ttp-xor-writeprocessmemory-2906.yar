rule TTP_XOR_WriteProcessMemory_2906 {
  strings:
    $key_2906 = { 7e 74 [2] 4c 56 [2] 4a 63 [2] 64 63 [2] 5b 7f }

  condition:
    any of them
}