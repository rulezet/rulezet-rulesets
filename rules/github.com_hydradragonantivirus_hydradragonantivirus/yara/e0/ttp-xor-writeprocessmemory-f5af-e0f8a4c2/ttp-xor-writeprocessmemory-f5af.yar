rule TTP_XOR_WriteProcessMemory_f5af {
  strings:
    $key_f5af = { a2 dd [2] 90 ff [2] 96 ca [2] b8 ca [2] 87 d6 }

  condition:
    any of them
}