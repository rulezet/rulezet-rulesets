rule TTP_XOR_WriteProcessMemory_d721 {
  strings:
    $key_d721 = { 80 53 [2] b2 71 [2] b4 44 [2] 9a 44 [2] a5 58 }

  condition:
    any of them
}