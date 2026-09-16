rule TTP_XOR_WriteProcessMemory_ec96 {
  strings:
    $key_ec96 = { bb e4 [2] 89 c6 [2] 8f f3 [2] a1 f3 [2] 9e ef }

  condition:
    any of them
}