rule TTP_XOR_WriteProcessMemory_f98d {
  strings:
    $key_f98d = { ae ff [2] 9c dd [2] 9a e8 [2] b4 e8 [2] 8b f4 }

  condition:
    any of them
}