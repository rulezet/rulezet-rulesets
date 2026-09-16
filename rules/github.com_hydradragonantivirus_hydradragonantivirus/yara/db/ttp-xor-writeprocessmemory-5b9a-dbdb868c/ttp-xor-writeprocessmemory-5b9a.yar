rule TTP_XOR_WriteProcessMemory_5b9a {
  strings:
    $key_5b9a = { 0c e8 [2] 3e ca [2] 38 ff [2] 16 ff [2] 29 e3 }

  condition:
    any of them
}