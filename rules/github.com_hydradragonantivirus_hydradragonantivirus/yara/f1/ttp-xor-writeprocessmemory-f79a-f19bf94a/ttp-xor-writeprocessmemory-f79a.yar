rule TTP_XOR_WriteProcessMemory_f79a {
  strings:
    $key_f79a = { a0 e8 [2] 92 ca [2] 94 ff [2] ba ff [2] 85 e3 }

  condition:
    any of them
}