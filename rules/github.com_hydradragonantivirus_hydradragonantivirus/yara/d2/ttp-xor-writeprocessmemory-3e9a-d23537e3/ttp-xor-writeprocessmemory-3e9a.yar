rule TTP_XOR_WriteProcessMemory_3e9a {
  strings:
    $key_3e9a = { 69 e8 [2] 5b ca [2] 5d ff [2] 73 ff [2] 4c e3 }

  condition:
    any of them
}