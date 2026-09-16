rule TTP_XOR_WriteProcessMemory_dd9a {
  strings:
    $key_dd9a = { 8a e8 [2] b8 ca [2] be ff [2] 90 ff [2] af e3 }

  condition:
    any of them
}