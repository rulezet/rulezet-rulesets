rule TTP_XOR_WriteProcessMemory_e7f4 {
  strings:
    $key_e7f4 = { b0 86 [2] 82 a4 [2] 84 91 [2] aa 91 [2] 95 8d }

  condition:
    any of them
}