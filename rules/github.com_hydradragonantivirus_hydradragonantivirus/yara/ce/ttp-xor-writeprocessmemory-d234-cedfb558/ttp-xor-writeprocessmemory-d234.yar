rule TTP_XOR_WriteProcessMemory_d234 {
  strings:
    $key_d234 = { 85 46 [2] b7 64 [2] b1 51 [2] 9f 51 [2] a0 4d }

  condition:
    any of them
}