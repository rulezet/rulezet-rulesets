rule TTP_XOR_WriteProcessMemory_e741 {
  strings:
    $key_e741 = { b0 33 [2] 82 11 [2] 84 24 [2] aa 24 [2] 95 38 }

  condition:
    any of them
}