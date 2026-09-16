rule TTP_XOR_WriteProcessMemory_cac6 {
  strings:
    $key_cac6 = { 9d b4 [2] af 96 [2] a9 a3 [2] 87 a3 [2] b8 bf }

  condition:
    any of them
}