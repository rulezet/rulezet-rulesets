rule TTP_XOR_WriteProcessMemory_cfb8 {
  strings:
    $key_cfb8 = { 98 ca [2] aa e8 [2] ac dd [2] 82 dd [2] bd c1 }

  condition:
    any of them
}