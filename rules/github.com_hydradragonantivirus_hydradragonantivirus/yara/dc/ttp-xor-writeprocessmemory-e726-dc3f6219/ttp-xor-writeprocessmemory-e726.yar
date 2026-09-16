rule TTP_XOR_WriteProcessMemory_e726 {
  strings:
    $key_e726 = { b0 54 [2] 82 76 [2] 84 43 [2] aa 43 [2] 95 5f }

  condition:
    any of them
}