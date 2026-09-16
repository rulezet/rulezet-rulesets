rule TTP_XOR_WriteProcessMemory_c6af {
  strings:
    $key_c6af = { 91 dd [2] a3 ff [2] a5 ca [2] 8b ca [2] b4 d6 }

  condition:
    any of them
}