rule TTP_XOR_WriteProcessMemory_aad2 {
  strings:
    $key_aad2 = { fd a0 [2] cf 82 [2] c9 b7 [2] e7 b7 [2] d8 ab }

  condition:
    any of them
}