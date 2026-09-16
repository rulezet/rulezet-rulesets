rule TTP_XOR_WriteProcessMemory_cfd5 {
  strings:
    $key_cfd5 = { 98 a7 [2] aa 85 [2] ac b0 [2] 82 b0 [2] bd ac }

  condition:
    any of them
}