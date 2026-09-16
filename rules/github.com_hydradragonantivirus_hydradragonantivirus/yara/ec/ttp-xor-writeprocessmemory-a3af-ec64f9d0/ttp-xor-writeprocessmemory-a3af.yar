rule TTP_XOR_WriteProcessMemory_a3af {
  strings:
    $key_a3af = { f4 dd [2] c6 ff [2] c0 ca [2] ee ca [2] d1 d6 }

  condition:
    any of them
}