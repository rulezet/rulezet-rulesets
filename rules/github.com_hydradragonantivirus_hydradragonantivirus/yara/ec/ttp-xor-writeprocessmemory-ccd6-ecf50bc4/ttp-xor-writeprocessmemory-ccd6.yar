rule TTP_XOR_WriteProcessMemory_ccd6 {
  strings:
    $key_ccd6 = { 9b a4 [2] a9 86 [2] af b3 [2] 81 b3 [2] be af }

  condition:
    any of them
}