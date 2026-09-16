rule TTP_XOR_WriteProcessMemory_e79a {
  strings:
    $key_e79a = { b0 e8 [2] 82 ca [2] 84 ff [2] aa ff [2] 95 e3 }

  condition:
    any of them
}