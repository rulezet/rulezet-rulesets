rule TTP_XOR_WriteProcessMemory_0d06 {
  strings:
    $key_0d06 = { 5a 74 [2] 68 56 [2] 6e 63 [2] 40 63 [2] 7f 7f }

  condition:
    any of them
}