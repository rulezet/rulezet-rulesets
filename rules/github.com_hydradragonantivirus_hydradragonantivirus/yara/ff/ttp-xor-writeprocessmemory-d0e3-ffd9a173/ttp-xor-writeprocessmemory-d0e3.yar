rule TTP_XOR_WriteProcessMemory_d0e3 {
  strings:
    $key_d0e3 = { 87 91 [2] b5 b3 [2] b3 86 [2] 9d 86 [2] a2 9a }

  condition:
    any of them
}