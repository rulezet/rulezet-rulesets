rule TTP_XOR_WriteProcessMemory_cc68 {
  strings:
    $key_cc68 = { 9b 1a [2] a9 38 [2] af 0d [2] 81 0d [2] be 11 }

  condition:
    any of them
}