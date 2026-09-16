rule TTP_XOR_WriteProcessMemory_f0af {
  strings:
    $key_f0af = { a7 dd [2] 95 ff [2] 93 ca [2] bd ca [2] 82 d6 }

  condition:
    any of them
}