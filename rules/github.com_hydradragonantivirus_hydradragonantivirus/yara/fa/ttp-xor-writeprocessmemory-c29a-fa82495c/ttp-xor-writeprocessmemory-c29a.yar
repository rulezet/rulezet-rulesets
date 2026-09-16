rule TTP_XOR_WriteProcessMemory_c29a {
  strings:
    $key_c29a = { 95 e8 [2] a7 ca [2] a1 ff [2] 8f ff [2] b0 e3 }

  condition:
    any of them
}