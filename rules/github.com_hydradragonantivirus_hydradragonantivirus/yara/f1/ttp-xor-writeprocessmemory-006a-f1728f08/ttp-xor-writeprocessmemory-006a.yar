rule TTP_XOR_WriteProcessMemory_006a {
  strings:
    $key_006a = { 57 18 [2] 65 3a [2] 63 0f [2] 4d 0f [2] 72 13 }

  condition:
    any of them
}