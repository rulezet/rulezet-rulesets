rule TTP_XOR_WriteProcessMemory_ec76 {
  strings:
    $key_ec76 = { bb 04 [2] 89 26 [2] 8f 13 [2] a1 13 [2] 9e 0f }

  condition:
    any of them
}