rule TTP_XOR_WriteProcessMemory_2d9a {
  strings:
    $key_2d9a = { 7a e8 [2] 48 ca [2] 4e ff [2] 60 ff [2] 5f e3 }

  condition:
    any of them
}