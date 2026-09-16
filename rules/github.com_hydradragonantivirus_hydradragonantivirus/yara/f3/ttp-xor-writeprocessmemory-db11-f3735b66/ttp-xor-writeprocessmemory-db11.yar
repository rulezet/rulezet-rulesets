rule TTP_XOR_WriteProcessMemory_db11 {
  strings:
    $key_db11 = { 8c 63 [2] be 41 [2] b8 74 [2] 96 74 [2] a9 68 }

  condition:
    any of them
}