rule TTP_XOR_WriteProcessMemory_b59a {
  strings:
    $key_b59a = { e2 e8 [2] d0 ca [2] d6 ff [2] f8 ff [2] c7 e3 }

  condition:
    any of them
}