rule TTP_XOR_WriteProcessMemory_238a {
  strings:
    $key_238a = { 74 f8 [2] 46 da [2] 40 ef [2] 6e ef [2] 51 f3 }

  condition:
    any of them
}