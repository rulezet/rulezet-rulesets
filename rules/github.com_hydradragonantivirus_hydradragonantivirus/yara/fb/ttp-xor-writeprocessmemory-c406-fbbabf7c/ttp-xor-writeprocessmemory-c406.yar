rule TTP_XOR_WriteProcessMemory_c406 {
  strings:
    $key_c406 = { 93 74 [2] a1 56 [2] a7 63 [2] 89 63 [2] b6 7f }

  condition:
    any of them
}