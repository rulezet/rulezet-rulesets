rule TTP_XOR_WriteProcessMemory_e69a {
  strings:
    $key_e69a = { b1 e8 [2] 83 ca [2] 85 ff [2] ab ff [2] 94 e3 }

  condition:
    any of them
}