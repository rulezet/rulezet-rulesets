rule TTP_XOR_WriteProcessMemory_8e9a {
  strings:
    $key_8e9a = { d9 e8 [2] eb ca [2] ed ff [2] c3 ff [2] fc e3 }

  condition:
    any of them
}