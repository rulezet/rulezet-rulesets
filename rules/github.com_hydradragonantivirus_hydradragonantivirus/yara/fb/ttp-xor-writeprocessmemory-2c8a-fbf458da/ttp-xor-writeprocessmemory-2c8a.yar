rule TTP_XOR_WriteProcessMemory_2c8a {
  strings:
    $key_2c8a = { 7b f8 [2] 49 da [2] 4f ef [2] 61 ef [2] 5e f3 }

  condition:
    any of them
}