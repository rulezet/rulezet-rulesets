rule TTP_XOR_WriteProcessMemory_aec6 {
  strings:
    $key_aec6 = { f9 b4 [2] cb 96 [2] cd a3 [2] e3 a3 [2] dc bf }

  condition:
    any of them
}