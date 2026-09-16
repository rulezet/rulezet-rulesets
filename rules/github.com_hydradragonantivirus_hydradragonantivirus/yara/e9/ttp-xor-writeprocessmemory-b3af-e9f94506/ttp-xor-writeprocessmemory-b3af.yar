rule TTP_XOR_WriteProcessMemory_b3af {
  strings:
    $key_b3af = { e4 dd [2] d6 ff [2] d0 ca [2] fe ca [2] c1 d6 }

  condition:
    any of them
}