rule TTP_XOR_WriteProcessMemory_2e9a {
  strings:
    $key_2e9a = { 79 e8 [2] 4b ca [2] 4d ff [2] 63 ff [2] 5c e3 }

  condition:
    any of them
}