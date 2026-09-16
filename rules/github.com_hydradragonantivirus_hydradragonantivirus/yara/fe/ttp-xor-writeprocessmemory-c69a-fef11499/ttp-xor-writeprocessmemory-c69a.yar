rule TTP_XOR_WriteProcessMemory_c69a {
  strings:
    $key_c69a = { 91 e8 [2] a3 ca [2] a5 ff [2] 8b ff [2] b4 e3 }

  condition:
    any of them
}