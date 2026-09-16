rule TTP_XOR_WriteProcessMemory_d417 {
  strings:
    $key_d417 = { 83 65 [2] b1 47 [2] b7 72 [2] 99 72 [2] a6 6e }

  condition:
    any of them
}