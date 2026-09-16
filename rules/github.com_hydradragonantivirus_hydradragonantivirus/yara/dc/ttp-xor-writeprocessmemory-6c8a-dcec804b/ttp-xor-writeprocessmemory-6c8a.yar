rule TTP_XOR_WriteProcessMemory_6c8a {
  strings:
    $key_6c8a = { 3b f8 [2] 09 da [2] 0f ef [2] 21 ef [2] 1e f3 }

  condition:
    any of them
}