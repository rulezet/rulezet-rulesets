rule TTP_XOR_WriteProcessMemory_db9a {
  strings:
    $key_db9a = { 8c e8 [2] be ca [2] b8 ff [2] 96 ff [2] a9 e3 }

  condition:
    any of them
}