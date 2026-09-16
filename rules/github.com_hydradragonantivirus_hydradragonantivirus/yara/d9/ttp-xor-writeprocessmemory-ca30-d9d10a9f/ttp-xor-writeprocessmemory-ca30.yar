rule TTP_XOR_WriteProcessMemory_ca30 {
  strings:
    $key_ca30 = { 9d 42 [2] af 60 [2] a9 55 [2] 87 55 [2] b8 49 }

  condition:
    any of them
}