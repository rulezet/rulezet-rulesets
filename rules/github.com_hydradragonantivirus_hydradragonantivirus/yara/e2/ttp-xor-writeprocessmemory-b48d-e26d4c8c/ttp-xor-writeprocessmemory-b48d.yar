rule TTP_XOR_WriteProcessMemory_b48d {
  strings:
    $key_b48d = { e3 ff [2] d1 dd [2] d7 e8 [2] f9 e8 [2] c6 f4 }

  condition:
    any of them
}