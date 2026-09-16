rule TTP_XOR_WriteProcessMemory_aa9a {
  strings:
    $key_aa9a = { fd e8 [2] cf ca [2] c9 ff [2] e7 ff [2] d8 e3 }

  condition:
    any of them
}