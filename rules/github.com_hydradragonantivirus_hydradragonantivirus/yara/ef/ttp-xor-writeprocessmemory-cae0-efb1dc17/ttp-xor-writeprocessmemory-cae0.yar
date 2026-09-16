rule TTP_XOR_WriteProcessMemory_cae0 {
  strings:
    $key_cae0 = { 9d 92 [2] af b0 [2] a9 85 [2] 87 85 [2] b8 99 }

  condition:
    any of them
}