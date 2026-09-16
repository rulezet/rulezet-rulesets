rule TTP_XOR_WriteProcessMemory_ccd3 {
  strings:
    $key_ccd3 = { 9b a1 [2] a9 83 [2] af b6 [2] 81 b6 [2] be aa }

  condition:
    any of them
}