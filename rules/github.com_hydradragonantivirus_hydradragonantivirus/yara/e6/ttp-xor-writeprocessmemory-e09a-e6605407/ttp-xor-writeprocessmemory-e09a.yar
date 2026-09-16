rule TTP_XOR_WriteProcessMemory_e09a {
  strings:
    $key_e09a = { b7 e8 [2] 85 ca [2] 83 ff [2] ad ff [2] 92 e3 }

  condition:
    any of them
}