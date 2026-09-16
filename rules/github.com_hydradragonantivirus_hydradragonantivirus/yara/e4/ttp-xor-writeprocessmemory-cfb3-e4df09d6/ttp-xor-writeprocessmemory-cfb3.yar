rule TTP_XOR_WriteProcessMemory_cfb3 {
  strings:
    $key_cfb3 = { 98 c1 [2] aa e3 [2] ac d6 [2] 82 d6 [2] bd ca }

  condition:
    any of them
}