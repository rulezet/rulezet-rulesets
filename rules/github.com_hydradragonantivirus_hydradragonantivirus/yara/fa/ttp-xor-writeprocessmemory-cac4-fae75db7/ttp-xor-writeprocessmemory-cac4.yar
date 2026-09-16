rule TTP_XOR_WriteProcessMemory_cac4 {
  strings:
    $key_cac4 = { 9d b6 [2] af 94 [2] a9 a1 [2] 87 a1 [2] b8 bd }

  condition:
    any of them
}