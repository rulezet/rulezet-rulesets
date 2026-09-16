rule TTP_XOR_WriteProcessMemory_c264 {
  strings:
    $key_c264 = { 95 16 [2] a7 34 [2] a1 01 [2] 8f 01 [2] b0 1d }

  condition:
    any of them
}