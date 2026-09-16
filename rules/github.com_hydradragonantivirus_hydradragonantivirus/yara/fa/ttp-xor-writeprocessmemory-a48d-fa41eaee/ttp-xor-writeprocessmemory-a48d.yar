rule TTP_XOR_WriteProcessMemory_a48d {
  strings:
    $key_a48d = { f3 ff [2] c1 dd [2] c7 e8 [2] e9 e8 [2] d6 f4 }

  condition:
    any of them
}