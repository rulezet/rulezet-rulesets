rule TTP_XOR_WriteProcessMemory_fdaf {
  strings:
    $key_fdaf = { aa dd [2] 98 ff [2] 9e ca [2] b0 ca [2] 8f d6 }

  condition:
    any of them
}