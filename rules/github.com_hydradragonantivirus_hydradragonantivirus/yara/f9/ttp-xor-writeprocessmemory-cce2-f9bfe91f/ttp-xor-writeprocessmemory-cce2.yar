rule TTP_XOR_WriteProcessMemory_cce2 {
  strings:
    $key_cce2 = { 9b 90 [2] a9 b2 [2] af 87 [2] 81 87 [2] be 9b }

  condition:
    any of them
}