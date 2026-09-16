rule TTP_XOR_WriteProcessMemory_cab5 {
  strings:
    $key_cab5 = { 9d c7 [2] af e5 [2] a9 d0 [2] 87 d0 [2] b8 cc }

  condition:
    any of them
}