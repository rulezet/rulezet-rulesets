rule TTP_XOR_WriteProcessMemory_ee8d {
  strings:
    $key_ee8d = { b9 ff [2] 8b dd [2] 8d e8 [2] a3 e8 [2] 9c f4 }

  condition:
    any of them
}