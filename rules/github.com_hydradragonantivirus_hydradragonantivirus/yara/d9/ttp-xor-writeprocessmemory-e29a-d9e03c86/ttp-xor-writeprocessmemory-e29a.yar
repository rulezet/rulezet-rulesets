rule TTP_XOR_WriteProcessMemory_e29a {
  strings:
    $key_e29a = { b5 e8 [2] 87 ca [2] 81 ff [2] af ff [2] 90 e3 }

  condition:
    any of them
}