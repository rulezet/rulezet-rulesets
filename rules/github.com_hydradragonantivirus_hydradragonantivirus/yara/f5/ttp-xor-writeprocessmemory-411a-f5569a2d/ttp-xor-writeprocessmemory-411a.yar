rule TTP_XOR_WriteProcessMemory_411a {
  strings:
    $key_411a = { 16 68 [2] 24 4a [2] 22 7f [2] 0c 7f [2] 33 63 }

  condition:
    any of them
}