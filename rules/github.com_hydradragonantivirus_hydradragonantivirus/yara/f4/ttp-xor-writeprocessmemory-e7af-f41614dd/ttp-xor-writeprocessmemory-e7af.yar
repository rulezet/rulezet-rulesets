rule TTP_XOR_WriteProcessMemory_e7af {
  strings:
    $key_e7af = { b0 dd [2] 82 ff [2] 84 ca [2] aa ca [2] 95 d6 }

  condition:
    any of them
}