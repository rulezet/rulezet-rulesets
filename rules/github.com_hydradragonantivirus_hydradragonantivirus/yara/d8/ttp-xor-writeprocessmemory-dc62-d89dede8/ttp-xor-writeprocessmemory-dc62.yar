rule TTP_XOR_WriteProcessMemory_dc62 {
  strings:
    $key_dc62 = { 8b 10 [2] b9 32 [2] bf 07 [2] 91 07 [2] ae 1b }

  condition:
    any of them
}