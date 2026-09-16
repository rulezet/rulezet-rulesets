rule TTP_XOR_WriteProcessMemory_cce9 {
  strings:
    $key_cce9 = { 9b 9b [2] a9 b9 [2] af 8c [2] 81 8c [2] be 90 }

  condition:
    any of them
}