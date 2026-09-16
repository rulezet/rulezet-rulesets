rule TTP_XOR_WriteProcessMemory_cc9a {
  strings:
    $key_cc9a = { 9b e8 [2] a9 ca [2] af ff [2] 81 ff [2] be e3 }

  condition:
    any of them
}