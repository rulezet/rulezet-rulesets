rule TTP_XOR_WriteProcessMemory_a29a {
  strings:
    $key_a29a = { f5 e8 [2] c7 ca [2] c1 ff [2] ef ff [2] d0 e3 }

  condition:
    any of them
}