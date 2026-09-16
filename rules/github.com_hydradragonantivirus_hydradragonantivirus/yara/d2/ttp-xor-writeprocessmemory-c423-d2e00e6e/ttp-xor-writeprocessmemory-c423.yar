rule TTP_XOR_WriteProcessMemory_c423 {
  strings:
    $key_c423 = { 93 51 [2] a1 73 [2] a7 46 [2] 89 46 [2] b6 5a }

  condition:
    any of them
}