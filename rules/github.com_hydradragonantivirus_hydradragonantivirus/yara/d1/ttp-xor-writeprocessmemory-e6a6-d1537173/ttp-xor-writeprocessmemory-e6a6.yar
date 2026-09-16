rule TTP_XOR_WriteProcessMemory_e6a6 {
  strings:
    $key_e6a6 = { b1 d4 [2] 83 f6 [2] 85 c3 [2] ab c3 [2] 94 df }

  condition:
    any of them
}