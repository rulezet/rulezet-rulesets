rule TTP_XOR_WriteProcessMemory_ca52 {
  strings:
    $key_ca52 = { 9d 20 [2] af 02 [2] a9 37 [2] 87 37 [2] b8 2b }

  condition:
    any of them
}