rule TTP_XOR_WriteProcessMemory_fdd7 {
  strings:
    $key_fdd7 = { aa a5 [2] 98 87 [2] 9e b2 [2] b0 b2 [2] 8f ae }

  condition:
    any of them
}