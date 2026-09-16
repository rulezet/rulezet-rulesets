rule TTP_XOR_WriteProcessMemory_c231 {
  strings:
    $key_c231 = { 95 43 [2] a7 61 [2] a1 54 [2] 8f 54 [2] b0 48 }

  condition:
    any of them
}