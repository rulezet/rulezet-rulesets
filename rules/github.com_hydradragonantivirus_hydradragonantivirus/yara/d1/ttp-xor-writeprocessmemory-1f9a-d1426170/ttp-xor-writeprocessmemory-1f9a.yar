rule TTP_XOR_WriteProcessMemory_1f9a {
  strings:
    $key_1f9a = { 48 e8 [2] 7a ca [2] 7c ff [2] 52 ff [2] 6d e3 }

  condition:
    any of them
}