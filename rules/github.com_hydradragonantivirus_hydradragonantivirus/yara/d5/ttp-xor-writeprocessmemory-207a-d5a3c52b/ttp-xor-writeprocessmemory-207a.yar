rule TTP_XOR_WriteProcessMemory_207a {
  strings:
    $key_207a = { 77 08 [2] 45 2a [2] 43 1f [2] 6d 1f [2] 52 03 }

  condition:
    any of them
}