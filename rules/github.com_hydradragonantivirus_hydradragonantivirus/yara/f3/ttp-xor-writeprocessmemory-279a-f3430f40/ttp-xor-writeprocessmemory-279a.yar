rule TTP_XOR_WriteProcessMemory_279a {
  strings:
    $key_279a = { 70 e8 [2] 42 ca [2] 44 ff [2] 6a ff [2] 55 e3 }

  condition:
    any of them
}