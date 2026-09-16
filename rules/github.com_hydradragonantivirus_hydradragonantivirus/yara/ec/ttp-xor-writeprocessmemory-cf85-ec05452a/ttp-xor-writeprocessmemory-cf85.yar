rule TTP_XOR_WriteProcessMemory_cf85 {
  strings:
    $key_cf85 = { 98 f7 [2] aa d5 [2] ac e0 [2] 82 e0 [2] bd fc }

  condition:
    any of them
}