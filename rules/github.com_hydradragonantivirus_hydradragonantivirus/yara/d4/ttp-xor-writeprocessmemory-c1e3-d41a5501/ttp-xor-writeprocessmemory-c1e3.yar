rule TTP_XOR_WriteProcessMemory_c1e3 {
  strings:
    $key_c1e3 = { 96 91 [2] a4 b3 [2] a2 86 [2] 8c 86 [2] b3 9a }

  condition:
    any of them
}