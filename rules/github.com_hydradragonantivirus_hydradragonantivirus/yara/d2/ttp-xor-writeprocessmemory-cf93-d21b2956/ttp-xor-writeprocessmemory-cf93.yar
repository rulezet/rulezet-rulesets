rule TTP_XOR_WriteProcessMemory_cf93 {
  strings:
    $key_cf93 = { 98 e1 [2] aa c3 [2] ac f6 [2] 82 f6 [2] bd ea }

  condition:
    any of them
}