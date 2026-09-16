rule TTP_XOR_WriteProcessMemory_129a {
  strings:
    $key_129a = { 45 e8 [2] 77 ca [2] 71 ff [2] 5f ff [2] 60 e3 }

  condition:
    any of them
}