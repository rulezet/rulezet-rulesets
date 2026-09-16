rule TTP_XOR_WriteProcessMemory_cfb0 {
  strings:
    $key_cfb0 = { 98 c2 [2] aa e0 [2] ac d5 [2] 82 d5 [2] bd c9 }

  condition:
    any of them
}