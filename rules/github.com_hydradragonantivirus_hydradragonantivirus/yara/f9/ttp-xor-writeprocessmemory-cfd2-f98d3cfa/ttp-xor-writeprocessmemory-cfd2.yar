rule TTP_XOR_WriteProcessMemory_cfd2 {
  strings:
    $key_cfd2 = { 98 a0 [2] aa 82 [2] ac b7 [2] 82 b7 [2] bd ab }

  condition:
    any of them
}