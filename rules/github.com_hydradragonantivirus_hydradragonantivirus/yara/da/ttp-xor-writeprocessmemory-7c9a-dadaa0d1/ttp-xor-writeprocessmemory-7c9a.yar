rule TTP_XOR_WriteProcessMemory_7c9a {
  strings:
    $key_7c9a = { 2b e8 [2] 19 ca [2] 1f ff [2] 31 ff [2] 0e e3 }

  condition:
    any of them
}