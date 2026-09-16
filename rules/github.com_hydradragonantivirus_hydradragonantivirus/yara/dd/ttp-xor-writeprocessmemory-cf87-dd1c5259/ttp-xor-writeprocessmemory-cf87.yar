rule TTP_XOR_WriteProcessMemory_cf87 {
  strings:
    $key_cf87 = { 98 f5 [2] aa d7 [2] ac e2 [2] 82 e2 [2] bd fe }

  condition:
    any of them
}