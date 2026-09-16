rule TTP_XOR_WriteProcessMemory_479a {
  strings:
    $key_479a = { 10 e8 [2] 22 ca [2] 24 ff [2] 0a ff [2] 35 e3 }

  condition:
    any of them
}