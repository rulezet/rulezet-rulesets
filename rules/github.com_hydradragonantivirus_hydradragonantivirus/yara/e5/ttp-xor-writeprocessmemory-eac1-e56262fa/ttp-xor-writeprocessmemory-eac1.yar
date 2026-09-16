rule TTP_XOR_WriteProcessMemory_eac1 {
  strings:
    $key_eac1 = { bd b3 [2] 8f 91 [2] 89 a4 [2] a7 a4 [2] 98 b8 }

  condition:
    any of them
}