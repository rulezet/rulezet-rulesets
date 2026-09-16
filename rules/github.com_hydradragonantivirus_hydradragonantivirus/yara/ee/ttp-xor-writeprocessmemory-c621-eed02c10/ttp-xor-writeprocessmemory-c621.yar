rule TTP_XOR_WriteProcessMemory_c621 {
  strings:
    $key_c621 = { 91 53 [2] a3 71 [2] a5 44 [2] 8b 44 [2] b4 58 }

  condition:
    any of them
}