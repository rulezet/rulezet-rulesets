rule TTP_XOR_WriteProcessMemory_edd5 {
  strings:
    $key_edd5 = { ba a7 [2] 88 85 [2] 8e b0 [2] a0 b0 [2] 9f ac }

  condition:
    any of them
}