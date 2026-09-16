rule TTP_XOR_WriteProcessMemory_c662 {
  strings:
    $key_c662 = { 91 10 [2] a3 32 [2] a5 07 [2] 8b 07 [2] b4 1b }

  condition:
    any of them
}