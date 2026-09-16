rule TTP_XOR_WriteProcessMemory_261a {
  strings:
    $key_261a = { 71 68 [2] 43 4a [2] 45 7f [2] 6b 7f [2] 54 63 }

  condition:
    any of them
}