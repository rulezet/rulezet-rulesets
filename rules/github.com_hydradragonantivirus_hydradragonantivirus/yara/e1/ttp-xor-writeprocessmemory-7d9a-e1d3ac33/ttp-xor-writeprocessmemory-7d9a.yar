rule TTP_XOR_WriteProcessMemory_7d9a {
  strings:
    $key_7d9a = { 2a e8 [2] 18 ca [2] 1e ff [2] 30 ff [2] 0f e3 }

  condition:
    any of them
}