rule TTP_XOR_WriteProcessMemory_b7af {
  strings:
    $key_b7af = { e0 dd [2] d2 ff [2] d4 ca [2] fa ca [2] c5 d6 }

  condition:
    any of them
}