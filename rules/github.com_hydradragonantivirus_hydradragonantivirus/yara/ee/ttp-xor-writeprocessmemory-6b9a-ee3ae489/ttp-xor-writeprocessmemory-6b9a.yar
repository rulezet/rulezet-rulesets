rule TTP_XOR_WriteProcessMemory_6b9a {
  strings:
    $key_6b9a = { 3c e8 [2] 0e ca [2] 08 ff [2] 26 ff [2] 19 e3 }

  condition:
    any of them
}