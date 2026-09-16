rule TTP_XOR_WriteProcessMemory_139a {
  strings:
    $key_139a = { 44 e8 [2] 76 ca [2] 70 ff [2] 5e ff [2] 61 e3 }

  condition:
    any of them
}