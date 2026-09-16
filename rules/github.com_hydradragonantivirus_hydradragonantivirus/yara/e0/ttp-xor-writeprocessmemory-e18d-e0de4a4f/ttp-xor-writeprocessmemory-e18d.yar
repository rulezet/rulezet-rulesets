rule TTP_XOR_WriteProcessMemory_e18d {
  strings:
    $key_e18d = { b6 ff [2] 84 dd [2] 82 e8 [2] ac e8 [2] 93 f4 }

  condition:
    any of them
}