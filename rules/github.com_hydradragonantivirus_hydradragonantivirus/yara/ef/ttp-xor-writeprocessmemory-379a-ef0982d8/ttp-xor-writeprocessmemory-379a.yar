rule TTP_XOR_WriteProcessMemory_379a {
  strings:
    $key_379a = { 60 e8 [2] 52 ca [2] 54 ff [2] 7a ff [2] 45 e3 }

  condition:
    any of them
}